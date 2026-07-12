#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <check.h>

/* access_log vive en src/server, fuera del archivo compartido; se incluye la
 * unidad directamente (mismo enfoque que metrics_test / users_test). */
#include "../src/server/access_log.c"

/* Crea un archivo temporal único y devuelve su ruta en `out`. */
static void make_temp_path(char *out, size_t cap)
{
    char tmpl[] = "/tmp/access_log_testXXXXXX";
    int fd = mkstemp(tmpl);
    ck_assert_int_ge(fd, 0);
    close(fd);
    snprintf(out, cap, "%s", tmpl);
}

/* Devuelve el i-ésimo token (separado por espacios) de `line` en `out`. */
static void token(const char *line, int idx, char *out, size_t cap)
{
    char copy[ACCESS_LOG_LINE_MAX];
    snprintf(copy, sizeof(copy), "%s", line);
    char *save = NULL;
    char *tok  = strtok_r(copy, " ", &save);
    for (int i = 0; i < idx && tok != NULL; i++) {
        tok = strtok_r(NULL, " ", &save);
    }
    snprintf(out, cap, "%s", tok != NULL ? tok : "");
}

START_TEST(test_empty_tail)
{
    char path[ACCESS_LOG_PATH_MAX];
    make_temp_path(path, sizeof(path));

    struct AccessLog l;
    ck_assert(access_log_open(&l, path));

    char lines[8][ACCESS_LOG_LINE_MAX];
    ck_assert_uint_eq(0, access_log_tail(&l, 10, lines, 8));

    access_log_close(&l);
    unlink(path);
}
END_TEST

START_TEST(test_record_fields)
{
    char path[ACCESS_LOG_PATH_MAX];
    make_temp_path(path, sizeof(path));

    struct AccessLog l;
    ck_assert(access_log_open(&l, path));
    access_log_record(&l, "alice", "example.com:443", "OK");

    char lines[8][ACCESS_LOG_LINE_MAX];
    ck_assert_uint_eq(1, access_log_tail(&l, 10, lines, 8));

    char t[ACCESS_LOG_LINE_MAX];
    /* timestamp ISO-8601 UTC: 2026-07-10T12:34:56Z (largo 20, 'T' y 'Z') */
    token(lines[0], 0, t, sizeof(t));
    ck_assert_uint_eq(20, strlen(t));
    ck_assert(t[10] == 'T');
    ck_assert(t[19] == 'Z');
    token(lines[0], 1, t, sizeof(t)); ck_assert_str_eq("alice", t);
    token(lines[0], 2, t, sizeof(t)); ck_assert_str_eq("CONNECT", t);
    token(lines[0], 3, t, sizeof(t)); ck_assert_str_eq("example.com:443", t);
    token(lines[0], 4, t, sizeof(t)); ck_assert_str_eq("OK", t);

    access_log_close(&l);
    unlink(path);
}
END_TEST

START_TEST(test_tail_newest_first_and_limit)
{
    char path[ACCESS_LOG_PATH_MAX];
    make_temp_path(path, sizeof(path));

    struct AccessLog l;
    ck_assert(access_log_open(&l, path));
    access_log_record(&l, "u", "d1:1", "OK");
    access_log_record(&l, "u", "d2:2", "OK");
    access_log_record(&l, "u", "d3:3", "OK");

    char lines[8][ACCESS_LOG_LINE_MAX];
    char d[ACCESS_LOG_LINE_MAX];

    /* últimas 2, más reciente primero: d3, d2 */
    ck_assert_uint_eq(2, access_log_tail(&l, 2, lines, 8));
    token(lines[0], 3, d, sizeof(d)); ck_assert_str_eq("d3:3", d);
    token(lines[1], 3, d, sizeof(d)); ck_assert_str_eq("d2:2", d);

    /* n mayor que lo disponible: devuelve las 3, más reciente primero */
    ck_assert_uint_eq(3, access_log_tail(&l, 10, lines, 8));
    token(lines[0], 3, d, sizeof(d)); ck_assert_str_eq("d3:3", d);
    token(lines[1], 3, d, sizeof(d)); ck_assert_str_eq("d2:2", d);
    token(lines[2], 3, d, sizeof(d)); ck_assert_str_eq("d1:1", d);

    access_log_close(&l);
    unlink(path);
}
END_TEST

START_TEST(test_tail_zero)
{
    char path[ACCESS_LOG_PATH_MAX];
    make_temp_path(path, sizeof(path));

    struct AccessLog l;
    ck_assert(access_log_open(&l, path));
    access_log_record(&l, "u", "d:1", "OK");

    char lines[8][ACCESS_LOG_LINE_MAX];
    ck_assert_uint_eq(0, access_log_tail(&l, 0, lines, 8));

    access_log_close(&l);
    unlink(path);
}
END_TEST

START_TEST(test_persists_across_reopen)
{
    char path[ACCESS_LOG_PATH_MAX];
    make_temp_path(path, sizeof(path));

    struct AccessLog l;
    ck_assert(access_log_open(&l, path));
    access_log_record(&l, "u", "before:1", "OK");
    access_log_close(&l); /* simula reinicio */

    ck_assert(access_log_open(&l, path));
    char lines[8][ACCESS_LOG_LINE_MAX];
    char d[ACCESS_LOG_LINE_MAX];

    /* el registro previo sigue estando tras reabrir */
    ck_assert_uint_eq(1, access_log_tail(&l, 10, lines, 8));
    token(lines[0], 3, d, sizeof(d)); ck_assert_str_eq("before:1", d);

    /* y se puede seguir anexando */
    access_log_record(&l, "u", "after:2", "OK");
    ck_assert_uint_eq(2, access_log_tail(&l, 10, lines, 8));
    token(lines[0], 3, d, sizeof(d)); ck_assert_str_eq("after:2", d);
    token(lines[1], 3, d, sizeof(d)); ck_assert_str_eq("before:1", d);

    access_log_close(&l);
    unlink(path);
}
END_TEST

START_TEST(test_disabled_is_noop)
{
    struct AccessLog l = { 0 }; /* fp == NULL: log deshabilitado */
    access_log_record(&l, "u", "d:1", "OK"); /* no debe crashear */

    char lines[8][ACCESS_LOG_LINE_MAX];
    ck_assert_uint_eq(0, access_log_tail(&l, 10, lines, 8));
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("access_log");
    TCase *tc = tcase_create("access_log");

    tcase_add_test(tc, test_empty_tail);
    tcase_add_test(tc, test_record_fields);
    tcase_add_test(tc, test_tail_newest_first_and_limit);
    tcase_add_test(tc, test_tail_zero);
    tcase_add_test(tc, test_persists_across_reopen);
    tcase_add_test(tc, test_disabled_is_noop);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(suite());
    int      number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
