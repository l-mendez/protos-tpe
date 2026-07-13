#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "access_log.h"
#include "args.h"
#include "config.h"
#include "mgmt.h"
#include "metrics.h"
#include "selector.h"
#include "server.h"
#include "socks5.h"
#include "users.h"

#define MAX_CONNECTIONS 1024

/* Cuenta las señales de terminación: la primera inicia el apagado ordenado
 * (deja de aceptar y drena), una segunda fuerza la salida inmediata. */
static volatile sig_atomic_t terminate = 0;

struct server_runtime {
    fd_selector       selector;
    int               passive;
    int               mng_passive;
    struct AccessLog *access_log;
};

static void
signal_handler(const int signal)
{
    (void)signal;
    terminate++;
}

static void
install_signal_handlers(void)
{
    /* Sin SA_RESTART para que la señal interrumpa el pselect del selector y el
     * loop reaccione de inmediato (pselect, además, nunca se reinicia). */
    struct sigaction sa = { .sa_handler = signal_handler };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

static int
server_cleanup(struct server_runtime *runtime, const int ret, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "%s\n", err);
    }
    socks5_resolver_pool_stop();
    if (runtime->selector != NULL) {
        selector_destroy(runtime->selector);
    }
    selector_close();
    if (runtime->passive >= 0) {
        close(runtime->passive);
    }
    if (runtime->mng_passive >= 0) {
        close(runtime->mng_passive);
    }
    if (runtime->access_log != NULL) {
        access_log_close(runtime->access_log);
    }
    return ret;
}

int
main(const int argc, char **argv)
{
    struct socks5args args;
    parse_args(argc, argv, &args);

    // almacenamiento de usuarios modificable en runtime
    static struct Users users;
    users_init(&users);
    for (int i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        users_add(&users, args.users[i].name, args.users[i].pass);
    }
    socks5_set_users(&users);

    /* Única instancia de métricas del proceso; vive durante toda la ejecución. */
    static struct Metrics metrics;
    metrics_init(&metrics);
    socks5_set_metrics(&metrics);

    /* Registro de accesos persistente. Si no se puede abrir, se continúa sin él
     * (el proxy sigue operativo; sólo no queda traza de accesos). */
    static struct AccessLog access_log;
    if (!access_log_open(&access_log, args.access_log_path)) {
        fprintf(stderr, "advertencia: no se pudo abrir el registro de accesos '%s'; "
                        "se continúa sin registro\n", args.access_log_path);
    }
    socks5_set_access_log(&access_log);

    /* Configuración runtime, modificable por el protocolo de monitoreo. El techo
     * de conexiones es la capacidad con la que se crea el selector. */
    static struct Config config;
    config_init(&config, MAX_CONNECTIONS);
    socks5_set_config(&config);

    static struct AdminCreds admin;
    admin_init(&admin, args.admin.name, args.admin.pass);

    static struct mgmt_deps mgmt_deps;
    mgmt_deps.users      = &users;
    mgmt_deps.metrics    = &metrics;
    mgmt_deps.config     = &config;
    mgmt_deps.access_log = &access_log;
    mgmt_deps.admin      = &admin;
    mgmt_set_deps(&mgmt_deps);

    /* Las escrituras a sockets cerrados no deben matar al proceso. */
    signal(SIGPIPE, SIG_IGN);
    install_signal_handlers();

    struct server_runtime runtime = {
        .selector    = NULL,
        .passive     = -1,
        .mng_passive = -1,
        .access_log  = &access_log,
    };

    runtime.passive = server_setup_passive(args.socks_addr, args.socks_port);
    if (runtime.passive < 0) {
        return server_cleanup(&runtime, 1,
                              "no se pudo crear el socket de escucha");
    }
    if (selector_fd_set_nio(runtime.passive) < 0) {
        return server_cleanup(&runtime, 1,
                              "no se pudo poner el socket en modo no bloqueante");
    }
    runtime.mng_passive = server_setup_passive(args.mng_addr, args.mng_port);
    if (runtime.mng_passive < 0) {
        return server_cleanup(&runtime, 1,
                              "no se pudo crear el socket de escucha de management");
    }
    if (selector_fd_set_nio(runtime.mng_passive) < 0) {
        return server_cleanup(&runtime, 1,
                              "no se pudo poner el socket de management en modo no bloqueante");
    }

    const struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        return server_cleanup(&runtime, 1,
                              "no se pudo inicializar el selector");
    }

    runtime.selector = selector_new(MAX_CONNECTIONS);
    if (runtime.selector == NULL) {
        return server_cleanup(&runtime, 1,
                              "no se pudo crear el selector");
    }
    if (!socks5_resolver_pool_start()) {
        return server_cleanup(&runtime, 1,
                              "no se pudo iniciar el pool de resolución DNS");
    }

    const fd_handler socks_passive_handler = { .handle_read = socks5_passive_accept };
    if (selector_register(runtime.selector, runtime.passive, &socks_passive_handler,
                          OP_READ, NULL) != SELECTOR_SUCCESS) {
        return server_cleanup(&runtime, 1,
                              "no se pudo registrar el socket de escucha");
    }
    const fd_handler mgmt_passive_handler = { .handle_read = mgmt_passive_accept };
    if (selector_register(runtime.selector, runtime.mng_passive, &mgmt_passive_handler,
                          OP_READ, NULL) != SELECTOR_SUCCESS) {
        return server_cleanup(&runtime, 1,
                              "no se pudo registrar el socket de escucha de management");
    }

    printf("socks5 escuchando en %s:%hu\n", args.socks_addr, args.socks_port);
    printf("management escuchando en %s:%hu\n", args.mng_addr, args.mng_port);

    bool accepting = true;
    while (true) {
        if (selector_select(runtime.selector) != SELECTOR_SUCCESS) {
            return server_cleanup(&runtime, 1, "fallo en selector_select");
        }

        socks5_reap_idle(runtime.selector);

        if (terminate) {
            if (accepting) {
                /* Apagado ordenado: dejar de aceptar nuevas conexiones y
                 * drenar las que siguen vivas. */
                if (runtime.passive >= 0) {
                    socks5_forget_paused_listener(runtime.passive);
                    selector_unregister_fd(runtime.selector, runtime.passive);
                    close(runtime.passive);
                    runtime.passive = -1;
                }
                if (runtime.mng_passive >= 0) {
                    selector_unregister_fd(runtime.selector, runtime.mng_passive);
                    close(runtime.mng_passive);
                    runtime.mng_passive = -1;
                }
                accepting  = false;
                printf("apagando: drenando %zu conexion(es) socks5 y %zu management\n",
                       socks5_active_connections(), mgmt_active_connections());
            }
            /* Salir cuando no quedan conexiones, o si llega una segunda señal. */
            if (terminate > 1) {
                break;
            }
            if (socks5_active_connections() == 0 && mgmt_active_connections() == 0) {
                break;
            }
        }
    }
    return server_cleanup(&runtime, 0, NULL);
}
