#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <check.h>

#include "selector.h"

/* The echo server lives in src/server, outside the shared archive the tests
 * link against, so the units are included directly to exercise them. Their
 * "" includes resolve relative to their own directory in src/server. */
#include "../src/server/server.c"
#include "../src/server/echo.c"

static fd_selector       test_selector;
static volatile sig_atomic_t test_stop;

static void *
run_selector(void *unused)
{
    (void)unused;
    while (!test_stop) {
        selector_select(test_selector);
    }
    return NULL;
}

static int
connect_to(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ck_assert_int_eq(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    return fd;
}

START_TEST(test_echo_returns_what_was_sent)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 100000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    test_selector = selector_new(64);
    ck_assert_ptr_nonnull(test_selector);

    /* port 0 -> the OS assigns a free port we read back with getsockname */
    int passive = server_setup_passive("127.0.0.1", 0);
    ck_assert_int_ge(passive, 0);

    struct sockaddr_in bound;
    socklen_t          bound_len = sizeof(bound);
    ck_assert_int_eq(getsockname(passive, (struct sockaddr *)&bound, &bound_len), 0);
    unsigned short port = ntohs(bound.sin_port);

    ck_assert_int_ge(selector_fd_set_nio(passive), 0);
    const fd_handler passive_handler = { .handle_read = echo_passive_accept };
    ck_assert_int_eq(
        selector_register(test_selector, passive, &passive_handler, OP_READ, NULL),
        SELECTOR_SUCCESS);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int         client = connect_to(port);
    const char *msg    = "hola mundo";
    size_t      len    = strlen(msg);
    ck_assert_int_eq(write(client, msg, len), (ssize_t)len);

    /* el echo puede llegar en varios segmentos: acumular hasta tenerlo entero */
    char   buf[64] = { 0 };
    size_t got     = 0;
    while (got < len) {
        ssize_t r = read(client, buf + got, sizeof(buf) - got);
        ck_assert_int_gt(r, 0);
        got += (size_t)r;
    }
    ck_assert_uint_eq(got, len);
    ck_assert_str_eq(buf, msg);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
}
END_TEST

/* Una lectura sobre un socket no bloqueante sin datos disponibles devuelve
 * EAGAIN; eso no es una desconexión y la conexión debe seguir registrada. */
START_TEST(test_read_eagain_keeps_connection)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 100000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    fd_selector s = selector_new(64);
    ck_assert_ptr_nonnull(s);

    int sv[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    ck_assert_int_ge(selector_fd_set_nio(sv[0]), 0);

    struct echo_conn *conn = malloc(sizeof(*conn));
    ck_assert_ptr_nonnull(conn);
    buffer_init(&conn->buffer, sizeof(conn->raw), conn->raw);
    ck_assert_int_eq(selector_register(s, sv[0], &echo_handler, OP_READ, conn),
                     SELECTOR_SUCCESS);
    active_connections++; /* simula la contabilidad que hace echo_passive_accept */

    /* nada escrito en sv[1] -> recv en sv[0] da EAGAIN */
    struct selector_key key = { .s = s, .fd = sv[0], .data = conn };
    echo_read(&key);

    /* si la conexión sobrevivió sigue registrada: desregistrarla ahora debe
     * tener éxito (si echo_read la hubiera cerrado, daría SELECTOR_IARGS). */
    ck_assert_int_eq(selector_unregister_fd(s, sv[0]), SELECTOR_SUCCESS);

    close(sv[1]);
    selector_destroy(s);
    selector_close();
}
END_TEST

/* El contador de conexiones (base del drenado en el apagado) sube al aceptar
 * y baja al cerrar. */
START_TEST(test_active_connections_lifecycle)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 100000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    fd_selector s = selector_new(64);
    ck_assert_ptr_nonnull(s);

    int passive = server_setup_passive("127.0.0.1", 0);
    ck_assert_int_ge(passive, 0);
    struct sockaddr_in bound;
    socklen_t          bound_len = sizeof(bound);
    ck_assert_int_eq(getsockname(passive, (struct sockaddr *)&bound, &bound_len), 0);

    size_t before = echo_active_connections();

    /* conexión pendiente en el backlog para que el accept tenga qué tomar */
    int client = connect_to(ntohs(bound.sin_port));

    struct selector_key key = { .s = s, .fd = passive, .data = NULL };
    echo_passive_accept(&key);
    ck_assert_uint_eq(echo_active_connections(), before + 1);

    /* destruir el selector desregistra la conexión -> echo_close la descuenta */
    selector_destroy(s);
    ck_assert_uint_eq(echo_active_connections(), before);

    selector_close();
    close(client);
    close(passive);
}
END_TEST

/* send() devolviendo 0 (sin progreso) no debe dejar la conexión girando en
 * OP_WRITE: hay que cerrarla. Se fuerza el caso con un buffer vacío, donde
 * send(fd, ptr, 0, ...) devuelve 0. */
START_TEST(test_write_no_progress_closes_connection)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 100000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    fd_selector s = selector_new(64);
    ck_assert_ptr_nonnull(s);

    int sv[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    ck_assert_int_ge(selector_fd_set_nio(sv[0]), 0);

    struct echo_conn *conn = malloc(sizeof(*conn));
    ck_assert_ptr_nonnull(conn);
    buffer_init(&conn->buffer, sizeof(conn->raw), conn->raw); /* buffer vacío */
    ck_assert_int_eq(selector_register(s, sv[0], &echo_handler, OP_WRITE, conn),
                     SELECTOR_SUCCESS);
    active_connections++; /* simula la contabilidad del accept */

    struct selector_key key = { .s = s, .fd = sv[0], .data = conn };
    echo_write(&key);

    /* la conexión debe haber quedado cerrada (desregistrada) */
    ck_assert_int_eq(selector_unregister_fd(s, sv[0]), SELECTOR_IARGS);

    close(sv[1]);
    selector_destroy(s);
    selector_close();
}
END_TEST

static Suite *
echo_suite(void)
{
    Suite *s   = suite_create("echo");
    TCase *tc  = tcase_create("roundtrip");
    tcase_add_test(tc, test_echo_returns_what_was_sent);
    tcase_add_test(tc, test_read_eagain_keeps_connection);
    tcase_add_test(tc, test_active_connections_lifecycle);
    tcase_add_test(tc, test_write_no_progress_closes_connection);
    suite_add_tcase(s, tc);
    return s;
}

int
main(void)
{
    SRunner *sr = srunner_create(echo_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
