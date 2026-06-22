#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "buffer.h"

/* The auth parser lives in src/server, outside the shared archive the tests link
 * against, so the unit is included directly (same approach as negotiation_test).
 * Its "" includes resolve relative to src/server (and -Isrc/shared for buffer.h). */
#include "../src/server/auth.c"

#define N(x) (sizeof(x) / sizeof((x)[0]))

/* Loads `len` bytes into `b` and feeds them to the parser in one shot. */
static auth_state feed_bytes(struct socks5_auth *p, buffer *b, const uint8_t *bytes, size_t len)
{
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    ck_assert_uint_ge(space, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
    return auth_parser_feed(p, b);
}

START_TEST(test_auth_happy)
{
    struct socks5_auth p;
    auth_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    /* VER=1, ULEN=4 "alan", PLEN=3 "pwd" */
    uint8_t msg[] = {0x01, 0x04, 'a', 'l', 'a', 'n', 0x03, 'p', 'w', 'd'};
    auth_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(AUTH_DONE, st);
    ck_assert(auth_done(&p));
    ck_assert_uint_eq(4, p.ulen);
    ck_assert_str_eq("alan", (char *)p.uname);
    ck_assert_uint_eq(3, p.plen);
    ck_assert_str_eq("pwd", (char *)p.passwd);
}
END_TEST

START_TEST(test_auth_wrong_version)
{
    struct socks5_auth p;
    auth_parser_init(&p);

    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x01, 'a', 0x01, 'b'}; /* VER=5 -> invalid (auth is 0x01) */
    auth_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(AUTH_ERROR, st);
}
END_TEST

/* RFC 1929 allows ULEN/PLEN of 0; the parser must skip the empty field. */
START_TEST(test_auth_empty_fields)
{
    struct socks5_auth p;
    auth_parser_init(&p);

    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x01, 0x00, 0x00}; /* empty username, empty password */
    auth_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(AUTH_DONE, st);
    ck_assert_uint_eq(0, p.ulen);
    ck_assert_str_eq("", (char *)p.uname);
    ck_assert_uint_eq(0, p.plen);
    ck_assert_str_eq("", (char *)p.passwd);
}
END_TEST

/* Partial reads: the same message delivered one byte per feed must parse
 * identically. This is the core "manejar lecturas parciales" requirement. */
START_TEST(test_auth_split_feed)
{
    struct socks5_auth p;
    auth_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x01, 0x04, 'a', 'l', 'a', 'n', 0x03, 'p', 'w', 'd'};
    auth_state st = AUTH_VER;
    for (size_t i = 0; i < N(msg); i++) {
        st = feed_bytes(&p, &buf, &msg[i], 1);
        if (i < N(msg) - 1) {
            ck_assert_int_ne(AUTH_DONE, st);
            ck_assert_int_ne(AUTH_ERROR, st);
        }
    }
    ck_assert_int_eq(AUTH_DONE, st);
    ck_assert_str_eq("alan", (char *)p.uname);
    ck_assert_str_eq("pwd", (char *)p.passwd);
}
END_TEST

START_TEST(test_auth_max_lengths)
{
    struct socks5_auth p;
    auth_parser_init(&p);

    uint8_t raw[600];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[1 + 1 + 255 + 1 + 255];
    size_t  i = 0;
    msg[i++] = 0x01;
    msg[i++] = 255;
    for (int k = 0; k < 255; k++) msg[i++] = 'u';
    msg[i++] = 255;
    for (int k = 0; k < 255; k++) msg[i++] = 'p';

    auth_state st = feed_bytes(&p, &buf, msg, i);
    ck_assert_int_eq(AUTH_DONE, st);
    ck_assert_uint_eq(255, p.ulen);
    ck_assert_uint_eq(255, p.plen);
    ck_assert_uint_eq('\0', p.uname[255]);
    ck_assert_uint_eq('\0', p.passwd[255]);
}
END_TEST

START_TEST(test_auth_reply_format)
{
    uint8_t outraw[8];
    buffer  out;
    buffer_init(&out, N(outraw), outraw);

    fill_auth_reply(&out, SOCKS5_AUTH_OK);
    ck_assert_uint_eq(0x01, buffer_read(&out)); /* VER del subprotocolo de auth */
    ck_assert_uint_eq(0x00, buffer_read(&out)); /* STATUS = success */

    buffer_reset(&out);
    fill_auth_reply(&out, SOCKS5_AUTH_FAIL);
    ck_assert_uint_eq(0x01, buffer_read(&out));
    ck_assert_uint_eq(0x01, buffer_read(&out));
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("auth");
    TCase *tc = tcase_create("auth");

    tcase_add_test(tc, test_auth_happy);
    tcase_add_test(tc, test_auth_wrong_version);
    tcase_add_test(tc, test_auth_empty_fields);
    tcase_add_test(tc, test_auth_split_feed);
    tcase_add_test(tc, test_auth_max_lengths);
    tcase_add_test(tc, test_auth_reply_format);
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
