#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "args.h"
#include "echo.h"
#include "selector.h"
#include "server.h"

#define MAX_CONNECTIONS 1024

static volatile sig_atomic_t terminate = 0;

static void
signal_handler(const int signal)
{
    (void)signal;
    terminate = 1;
}

int
main(const int argc, char **argv)
{
    struct socks5args args;
    parse_args(argc, argv, &args);

    /* Las escrituras a sockets cerrados no deben matar al proceso. */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

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

    const fd_handler passive_handler = { .handle_read = echo_passive_accept };
    if (selector_register(selector, passive, &passive_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        err = "no se pudo registrar el socket de escucha";
        goto finally;
    }

    printf("echo escuchando en %s:%hu\n", args.socks_addr, args.socks_port);

    while (!terminate) {
        if (selector_select(selector) != SELECTOR_SUCCESS) {
            err = "fallo en selector_select";
            goto finally;
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
