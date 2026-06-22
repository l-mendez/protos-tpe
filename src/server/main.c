#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "args.h"
#include "selector.h"
#include "server.h"
#include "socks5.h"

#define MAX_CONNECTIONS 1024

/* Cuenta las señales de terminación: la primera inicia el apagado ordenado
 * (deja de aceptar y drena), una segunda fuerza la salida inmediata. */
static volatile sig_atomic_t terminate = 0;

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

int
main(const int argc, char **argv)
{
    struct socks5args args;
    parse_args(argc, argv, &args);
    socks5_set_users(&args);

    /* Las escrituras a sockets cerrados no deben matar al proceso. */
    signal(SIGPIPE, SIG_IGN);
    install_signal_handlers();

    int          ret      = 1;
    const char  *err      = NULL;
    fd_selector  selector = NULL;

    int passive = server_setup_passive(args.socks_addr, args.socks_port);
    if (passive < 0) {
        err = "no se pudo crear el socket de escucha";
        goto finally;
    }
    if (selector_fd_set_nio(passive) < 0) {
        err = "no se pudo poner el socket en modo no bloqueante";
        goto finally;
    }

    const struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        err = "no se pudo inicializar el selector";
        goto finally;
    }

    selector = selector_new(MAX_CONNECTIONS);
    if (selector == NULL) {
        err = "no se pudo crear el selector";
        goto finally;
    }

    const fd_handler passive_handler = { .handle_read = socks5_passive_accept };
    if (selector_register(selector, passive, &passive_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        err = "no se pudo registrar el socket de escucha";
        goto finally;
    }

    printf("socks5 escuchando en %s:%hu\n", args.socks_addr, args.socks_port);

    bool accepting = true;
    while (true) {
        if (selector_select(selector) != SELECTOR_SUCCESS) {
            err = "fallo en selector_select";
            goto finally;
        }

        socks5_reap_idle(selector);

        if (terminate) {
            if (accepting) {
                /* Apagado ordenado: dejar de aceptar nuevas conexiones y
                 * drenar las que siguen vivas. */
                selector_unregister_fd(selector, passive);
                close(passive);
                passive    = -1;
                accepting  = false;
                printf("apagando: drenando %zu conexion(es)\n",
                       socks5_active_connections());
            }
            /* Salir cuando no quedan conexiones, o si llega una segunda señal. */
            if (socks5_active_connections() == 0 || terminate > 1) {
                break;
            }
        }
    }
    ret = 0;

finally:
    if (err != NULL) {
        fprintf(stderr, "%s\n", err);
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();
    if (passive >= 0) {
        close(passive);
    }
    return ret;
}
