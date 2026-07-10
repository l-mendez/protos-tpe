#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "args.h"
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
    fd_selector selector;
    int         passive;
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

    /* Las escrituras a sockets cerrados no deben matar al proceso. */
    signal(SIGPIPE, SIG_IGN);
    install_signal_handlers();

    struct server_runtime runtime = {
        .selector = NULL,
        .passive  = -1,
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

    const fd_handler passive_handler = { .handle_read = socks5_passive_accept };
    if (selector_register(runtime.selector, runtime.passive, &passive_handler,
                          OP_READ, NULL) != SELECTOR_SUCCESS) {
        return server_cleanup(&runtime, 1,
                              "no se pudo registrar el socket de escucha");
    }

    printf("socks5 escuchando en %s:%hu\n", args.socks_addr, args.socks_port);

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
                selector_unregister_fd(runtime.selector, runtime.passive);
                close(runtime.passive);
                runtime.passive = -1;
                accepting  = false;
                printf("apagando: drenando %zu conexion(es)\n",
                       socks5_active_connections());
            }
            /* Salir cuando no quedan conexiones, o si llega una segunda señal. */
            if (terminate > 1) {
                break;
            }
            if (socks5_active_connections() == 0) {
                break;
            }
        }
    }
    return server_cleanup(&runtime, 0, NULL);
}
