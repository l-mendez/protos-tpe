#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "buffer.h"

/* mgmt_parser vive en src/server; se incluye directo (como los demás tests). */
#include "../src/server/mgmt_parser.c"

/* Escribe `s` (sin el NUL) en el buffer. */
static void put(buffer *b, const char *s)
{
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    size_t   n   = strlen(s);
    ck_assert_uint_ge(space, n);
    memcpy(ptr, s, n);
    buffer_write_adv(b, n);
}

/* ------------------------------------------------------------ framing */

START_TEST(test_line_simple)
{
    struct mgmt_parser p;
    mgmt_parser_init(&p);
    uint8_t raw[128];
    buffer  b;
    buffer_init(&b, sizeof(raw), raw);

    put(&b, "AUTH admin pass\n");
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("AUTH admin pass", p.line);
}
END_TEST

START_TEST(test_line_strips_cr)
{
    struct mgmt_parser p;
    mgmt_parser_init(&p);
    uint8_t raw[128];
    buffer  b;
    buffer_init(&b, sizeof(raw), raw);

    put(&b, "HELP\r\n");
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("HELP", p.line);
}
END_TEST

START_TEST(test_line_empty)
{
    struct mgmt_parser p;
    mgmt_parser_init(&p);
    uint8_t raw[128];
    buffer  b;
    buffer_init(&b, sizeof(raw), raw);

    put(&b, "\n");
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("", p.line);
    ck_assert_uint_eq(0, p.len);
}
END_TEST

START_TEST(test_line_partial_then_complete)
{
    struct mgmt_parser p;
    mgmt_parser_init(&p);
    uint8_t raw[128];
    buffer  b;
    buffer_init(&b, sizeof(raw), raw);

    put(&b, "MET");
    ck_assert_int_eq(MGMT_LINE_INCOMPLETE, mgmt_parser_feed(&p, &b));
    put(&b, "RICS\n");
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("METRICS", p.line);
}
END_TEST

START_TEST(test_line_pipelined)
{
    struct mgmt_parser p;
    mgmt_parser_init(&p);
    uint8_t raw[128];
    buffer  b;
    buffer_init(&b, sizeof(raw), raw);

    put(&b, "A\nB\n");
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("A", p.line);
    mgmt_parser_reset(&p);
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("B", p.line);
    mgmt_parser_reset(&p);
    ck_assert_int_eq(MGMT_LINE_INCOMPLETE, mgmt_parser_feed(&p, &b));
}
END_TEST

START_TEST(test_line_too_long_then_recovers)
{
    struct mgmt_parser p;
    mgmt_parser_init(&p);
    uint8_t raw[6000];
    buffer  b;
    buffer_init(&b, sizeof(raw), raw);

    /* 5000 bytes de contenido + LF: excede MGMT_LINE_MAX */
    char big[5000 + 2];
    memset(big, 'x', 5000);
    big[5000] = '\n';
    big[5001] = '\0';
    put(&b, big);
    ck_assert_int_eq(MGMT_LINE_TOO_LONG, mgmt_parser_feed(&p, &b));

    /* tras resetear, la próxima línea se parsea normalmente */
    mgmt_parser_reset(&p);
    put(&b, "OK\n");
    ck_assert_int_eq(MGMT_LINE_READY, mgmt_parser_feed(&p, &b));
    ck_assert_str_eq("OK", p.line);
}
END_TEST

/* ------------------------------------------------------------ tokenize */

START_TEST(test_tokenize_basic)
{
    char line[] = "AUTH admin pass";
    char *argv[8];
    int argc = mgmt_tokenize(line, argv, 8);
    ck_assert_int_eq(3, argc);
    ck_assert_str_eq("AUTH", argv[0]);
    ck_assert_str_eq("admin", argv[1]);
    ck_assert_str_eq("pass", argv[2]);
}
END_TEST

START_TEST(test_tokenize_single_and_empty)
{
    char one[] = "METRICS";
    char *argv[8];
    ck_assert_int_eq(1, mgmt_tokenize(one, argv, 8));
    ck_assert_str_eq("METRICS", argv[0]);

    char empty[] = "";
    ck_assert_int_eq(0, mgmt_tokenize(empty, argv, 8));
}
END_TEST

START_TEST(test_tokenize_collapses_spaces)
{
    char line[] = "  SET   conn_timeout  30 ";
    char *argv[8];
    int argc = mgmt_tokenize(line, argv, 8);
    ck_assert_int_eq(3, argc);
    ck_assert_str_eq("SET", argv[0]);
    ck_assert_str_eq("conn_timeout", argv[1]);
    ck_assert_str_eq("30", argv[2]);
}
END_TEST

START_TEST(test_tokenize_caps_at_max)
{
    char line[] = "a b c d e";
    char *argv[3];
    int argc = mgmt_tokenize(line, argv, 3);
    ck_assert_int_eq(3, argc);
    ck_assert_str_eq("a", argv[0]);
    ck_assert_str_eq("b", argv[1]);
    ck_assert_str_eq("c", argv[2]);
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("mgmt_parser");
    TCase *tc = tcase_create("mgmt_parser");

    tcase_add_test(tc, test_line_simple);
    tcase_add_test(tc, test_line_strips_cr);
    tcase_add_test(tc, test_line_empty);
    tcase_add_test(tc, test_line_partial_then_complete);
    tcase_add_test(tc, test_line_pipelined);
    tcase_add_test(tc, test_line_too_long_then_recovers);
    tcase_add_test(tc, test_tokenize_basic);
    tcase_add_test(tc, test_tokenize_single_and_empty);
    tcase_add_test(tc, test_tokenize_collapses_spaces);
    tcase_add_test(tc, test_tokenize_caps_at_max);
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
