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
