#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "buffer.h"

/* Unidades de src/server incluidas directamente (como los demás tests). */
#include "../src/server/users.c"
#include "../src/server/metrics.c"
#include "../src/server/config.c"
#include "../src/server/access_log.c"
#include "../src/server/mgmt_parser.c"
#include "../src/server/mgmt.c"

/* Contexto de prueba: deps reales + sesión. */
struct ctx {
    struct Users      users;
    struct Metrics    metrics;
    struct Config     config;
    struct AccessLog  alog;
    struct AdminCreds admin;
    struct mgmt_deps  deps;
    struct mgmt_session s;
};

static void ctx_init(struct ctx *c)
{
    users_init(&c->users);
    metrics_init(&c->metrics);
    config_init(&c->config, 1024);
    c->alog = (struct AccessLog){ 0 }; /* log deshabilitado por defecto */
    admin_init(&c->admin, "admin", "secret");
    c->deps = (struct mgmt_deps){
        .users = &c->users, .metrics = &c->metrics, .config = &c->config,
        .access_log = &c->alog, .admin = &c->admin,
    };
    mgmt_session_init(&c->s, &c->deps);
}

/* Ejecuta una línea y devuelve la respuesta como C-string en `out`. */
static bool run(struct ctx *c, const char *cmd, char *out, size_t cap)
{
    char line[600];
    snprintf(line, sizeof(line), "%s", cmd);
    static uint8_t raw[8192];
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    bool close_after = mgmt_handle_line(&c->s, line, &b);
    size_t   n;
    uint8_t *p = buffer_read_ptr(&b, &n);
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return close_after;
}

/* auth helper */
static void auth_ok(struct ctx *c)
{
    char out[256];
    run(c, "AUTH admin secret", out, sizeof(out));
    ck_assert_str_eq("+OK authenticated\n", out);
}

START_TEST(test_requires_auth)
{
    struct ctx c; ctx_init(&c);
    char out[256];
    run(&c, "METRICS", out, sizeof(out));
    ck_assert_str_eq("-ERR not authenticated\n", out);
    run(&c, "METRICS extra", out, sizeof(out));
    ck_assert_str_eq("-ERR not authenticated\n", out);
}
END_TEST

START_TEST(test_auth_bad_then_ok)
{
    struct ctx c; ctx_init(&c);
    char out[256];
    run(&c, "AUTH admin wrong", out, sizeof(out));
    ck_assert_str_eq("-ERR bad credentials\n", out);
    ck_assert(!c.s.authenticated);

    run(&c, "AUTH admin secret", out, sizeof(out));
    ck_assert_str_eq("+OK authenticated\n", out);
    ck_assert(c.s.authenticated);

    run(&c, "AUTH admin secret", out, sizeof(out));
    ck_assert_str_eq("-ERR already authenticated\n", out);
}
END_TEST

START_TEST(test_auth_case_insensitive_command)
{
    struct ctx c; ctx_init(&c);
    char out[256];
    run(&c, "auth admin secret", out, sizeof(out));
    ck_assert_str_eq("+OK authenticated\n", out);
}
END_TEST

START_TEST(test_unknown_command)
{
    struct ctx c; ctx_init(&c);
    auth_ok(&c);
    char out[256];
    run(&c, "FOOBAR", out, sizeof(out));
    ck_assert_str_eq("-ERR unknown command\n", out);
}
END_TEST

START_TEST(test_help_and_quit_pre_auth)
{
    struct ctx c; ctx_init(&c);
    char out[512];
    run(&c, "HELP", out, sizeof(out));
    ck_assert(strncmp(out, "+OK ", 4) == 0); /* disponible sin auth */

    bool close_after = run(&c, "QUIT", out, sizeof(out));
    ck_assert_str_eq("+OK bye\n", out);
    ck_assert(close_after);
}
END_TEST

START_TEST(test_fixed_arity_commands_reject_extra_args)
{
    struct ctx c; ctx_init(&c);
    auth_ok(&c);
    char out[256];

    ck_assert(!run(&c, "METRICS extra", out, sizeof(out)));
    ck_assert_str_eq("-ERR invalid\n", out);
    ck_assert(!run(&c, "LIST-USERS extra", out, sizeof(out)));
    ck_assert_str_eq("-ERR invalid\n", out);
    ck_assert(!run(&c, "GET-CONFIG extra", out, sizeof(out)));
    ck_assert_str_eq("-ERR invalid\n", out);
    ck_assert(!run(&c, "HELP extra", out, sizeof(out)));
    ck_assert_str_eq("-ERR invalid\n", out);
    ck_assert(!run(&c, "QUIT extra", out, sizeof(out)));
    ck_assert_str_eq("-ERR invalid\n", out);
}
END_TEST

START_TEST(test_process_input_lines_keeps_responses_atomic)
{
    struct ctx c; ctx_init(&c);
    struct mgmt_conn conn = { 0 };
    mgmt_session_init(&conn.session, &c.deps);
    mgmt_parser_init(&conn.parser);
    buffer_init(&conn.read_buffer, sizeof(conn.raw_read), conn.raw_read);
    buffer_init(&conn.write_buffer, sizeof(conn.raw_write), conn.raw_write);

    char expected[512];
    run(&c, "HELP", expected, sizeof(expected));
    const size_t response_size = strlen(expected);
    const char command[] = "HELP\n";
    const size_t command_count = (sizeof(conn.raw_write) / response_size) + 1;
    ck_assert_uint_le(command_count * (sizeof(command) - 1), sizeof(conn.raw_read));
    for (size_t i = 0; i < command_count; i++) {
        size_t space;
        uint8_t *dst = buffer_write_ptr(&conn.read_buffer, &space);
        ck_assert_uint_ge(space, sizeof(command) - 1);
        memcpy(dst, command, sizeof(command) - 1);
        buffer_write_adv(&conn.read_buffer, sizeof(command) - 1);
    }

    process_input_lines(&conn);

    size_t output_size;
    (void)buffer_read_ptr(&conn.write_buffer, &output_size);
    ck_assert_uint_eq(0, output_size % response_size);

    size_t input_left;
    (void)buffer_read_ptr(&conn.read_buffer, &input_left);
    ck_assert_uint_eq((command_count - (output_size / response_size)) *
                      (sizeof(command) - 1),
                      input_left);
}
END_TEST

START_TEST(test_mgmt_read_resumes_buffered_input_after_sync_flush)
{
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 50000000 },
    };
    ck_assert_int_eq(SELECTOR_SUCCESS, selector_init(&conf));
    fd_selector selector = selector_new(64);
    ck_assert_ptr_nonnull(selector);

    int fds[2];
    ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ck_assert_int_eq(0, selector_fd_set_nio(fds[0]));

    struct ctx c; ctx_init(&c);
    struct mgmt_conn conn = { .fd = fds[0] };
    mgmt_session_init(&conn.session, &c.deps);
    mgmt_parser_init(&conn.parser);
    buffer_init(&conn.read_buffer, sizeof(conn.raw_read), conn.raw_read);
    buffer_init(&conn.write_buffer, sizeof(conn.raw_write), conn.raw_write);

    static const fd_handler test_handler = { 0 };
    ck_assert_int_eq(SELECTOR_SUCCESS,
                     selector_register(selector, fds[0], &test_handler, OP_READ, &conn));
    const char commands[] = "HELP\nHELP\n";
    ck_assert_int_eq((ssize_t)(sizeof(commands) - 1),
                     write(fds[1], commands, sizeof(commands) - 1));

    struct selector_key key = { .s = selector, .fd = fds[0], .data = &conn };
    mgmt_read(&key);

    size_t input_left;
    (void)buffer_read_ptr(&conn.read_buffer, &input_left);
    ck_assert_uint_eq(0, input_left);

    selector_destroy(selector);
    selector_close();
    close(fds[0]);
    close(fds[1]);
}
END_TEST

START_TEST(test_metrics)
{
    struct ctx c; ctx_init(&c);
    metrics_connection_opened(&c.metrics); /* active=1, hist=1 */
    users_add(&c.users, "u", "p");
    auth_ok(&c);

    char out[512];
    run(&c, "METRICS", out, sizeof(out));
    ck_assert(strncmp(out, "+OK 7\n", 6) == 0);
    ck_assert_ptr_nonnull(strstr(out, "active_connections 1\n"));
    ck_assert_ptr_nonnull(strstr(out, "historical_connections 1\n"));
    ck_assert_ptr_nonnull(strstr(out, "users_count 1\n"));
}
END_TEST

START_TEST(test_user_lifecycle)
{
    struct ctx c; ctx_init(&c);
    auth_ok(&c);
    char out[512];

    run(&c, "ADD-USER bob pw", out, sizeof(out));
    ck_assert_str_eq("+OK user added\n", out);
    ck_assert(users_exists(&c.users, "bob"));

    run(&c, "ADD-USER bob other", out, sizeof(out));
    ck_assert_str_eq("-ERR user exists\n", out);

    run(&c, "LIST-USERS", out, sizeof(out));
    ck_assert(strncmp(out, "+OK 1\n", 6) == 0);
    ck_assert_ptr_nonnull(strstr(out, "bob\n"));

    run(&c, "DEL-USER bob", out, sizeof(out));
    ck_assert_str_eq("+OK user removed\n", out);

    run(&c, "DEL-USER bob", out, sizeof(out));
    ck_assert_str_eq("-ERR no such user\n", out);
}
END_TEST

START_TEST(test_add_user_bad_args)
{
    struct ctx c; ctx_init(&c);
    auth_ok(&c);
    char out[256];
    run(&c, "ADD-USER onlyname", out, sizeof(out));
    ck_assert_str_eq("-ERR invalid\n", out);
}
END_TEST

START_TEST(test_get_and_set_config)
{
    struct ctx c; ctx_init(&c);
    auth_ok(&c);
    char out[256];

    run(&c, "GET-CONFIG", out, sizeof(out));
    ck_assert(strncmp(out, "+OK 3\n", 6) == 0);
    ck_assert_ptr_nonnull(strstr(out, "conn_timeout 60\n"));

    run(&c, "SET conn_timeout 30", out, sizeof(out));
    ck_assert_str_eq("+OK conn_timeout = 30\n", out);
    ck_assert_uint_eq(30, config_conn_timeout(&c.config));

    run(&c, "SET conn_timeout 0", out, sizeof(out)); /* fuera de rango */
    ck_assert_str_eq("-ERR invalid value\n", out);

    run(&c, "SET conn_timeout abc", out, sizeof(out)); /* no numérico */
    ck_assert_str_eq("-ERR invalid value\n", out);

    run(&c, "SET bogus 5", out, sizeof(out)); /* clave desconocida */
    ck_assert_str_eq("-ERR unknown key\n", out);
}
END_TEST

START_TEST(test_log)
{
    struct ctx c; ctx_init(&c);
    /* habilitar log en archivo temporal */
    char path[] = "/tmp/mgmt_logtestXXXXXX";
    int fd = mkstemp(path); ck_assert_int_ge(fd, 0); close(fd);
    ck_assert(access_log_open(&c.alog, path));
    access_log_record(&c.alog, "alice", "example.com:443", "OK");

    auth_ok(&c);
    char out[512];
    run(&c, "LOG 10", out, sizeof(out));
    ck_assert(strncmp(out, "+OK 1\n", 6) == 0);
    ck_assert_ptr_nonnull(strstr(out, "alice CONNECT example.com:443 OK"));

    access_log_close(&c.alog);
    unlink(path);
}
END_TEST

START_TEST(test_passwd)
{
    struct ctx c; ctx_init(&c);
    auth_ok(&c);
    char out[256];

    run(&c, "PASSWD newpass", out, sizeof(out));
    ck_assert_str_eq("+OK password changed\n", out);

    /* nueva sesión: la contraseña vieja falla, la nueva funciona */
    struct mgmt_session s2; mgmt_session_init(&s2, &c.deps); c.s = s2;
    run(&c, "AUTH admin secret", out, sizeof(out));
    ck_assert_str_eq("-ERR bad credentials\n", out);
    run(&c, "AUTH admin newpass", out, sizeof(out));
    ck_assert_str_eq("+OK authenticated\n", out);
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("mgmt");
    TCase *tc = tcase_create("mgmt");
    tcase_add_test(tc, test_requires_auth);
    tcase_add_test(tc, test_auth_bad_then_ok);
    tcase_add_test(tc, test_auth_case_insensitive_command);
    tcase_add_test(tc, test_unknown_command);
    tcase_add_test(tc, test_help_and_quit_pre_auth);
    tcase_add_test(tc, test_fixed_arity_commands_reject_extra_args);
    tcase_add_test(tc, test_process_input_lines_keeps_responses_atomic);
    tcase_add_test(tc, test_mgmt_read_resumes_buffered_input_after_sync_flush);
    tcase_add_test(tc, test_metrics);
    tcase_add_test(tc, test_user_lifecycle);
    tcase_add_test(tc, test_add_user_bad_args);
    tcase_add_test(tc, test_get_and_set_config);
    tcase_add_test(tc, test_log);
    tcase_add_test(tc, test_passwd);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
