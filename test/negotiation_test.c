#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "buffer.h"

/* The negotiation parser lives in src/server, outside the shared archive the
 * tests link against, so the unit is included directly. Its "" includes resolve
 * relative to its own directory in src/server (and -Isrc/shared for buffer.h). */
#include "../src/server/negotiation.c"

#define N(x) (sizeof(x) / sizeof((x)[0]))

/* Loads `len` bytes into `b` and feeds them to the parser in one shot. */
static neg_state feed_bytes(struct negotiation_parser *p, buffer *b, const uint8_t *bytes, size_t len)
{
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    ck_assert_uint_ge(space, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
    return negotiation_parser_feed(p, b);
}

START_TEST(test_neg_noauth_happy)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t   raw[32];
    buffer    buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x01, 0x00}; /* VER=5, NMETHODS=1, no-auth */
    neg_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(NEG_DONE, st);
    ck_assert(negotiation_done(&p));
    ck_assert(p.has_noauth);
    ck_assert(!p.has_userpass);
}
END_TEST

START_TEST(test_neg_userpass_happy)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t raw[32];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x02, 0x00, 0x02}; /* offers no-auth AND user/pass */
    neg_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(NEG_DONE, st);
    ck_assert(p.has_noauth);
    ck_assert(p.has_userpass);
}
END_TEST

START_TEST(test_neg_wrong_version)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t raw[32];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x04, 0x01, 0x00}; /* VER=4 -> invalid */
    neg_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(NEG_INVALID, st);
}
END_TEST

/* Partial reads: the same message delivered one byte per feed must parse
 * identically. This is the core "manejar lecturas parciales" requirement. */
START_TEST(test_neg_split_feed)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t raw[32];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x02, 0x00, 0x02};
    neg_state st = NEG_VERSION;
    for (size_t i = 0; i < N(msg); i++) {
        st = feed_bytes(&p, &buf, &msg[i], 1);
        if (i < N(msg) - 1) {
            ck_assert_int_ne(NEG_DONE, st);
            ck_assert_int_ne(NEG_INVALID, st);
        }
    }
    ck_assert_int_eq(NEG_DONE, st);
    ck_assert(p.has_userpass);
}
END_TEST

START_TEST(test_neg_reply_prefers_userpass)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);
    uint8_t inraw[32];
    buffer  in;
    buffer_init(&in, N(inraw), inraw);
    uint8_t msg[] = {0x05, 0x02, 0x00, 0x02};
    feed_bytes(&p, &in, msg, N(msg));

    uint8_t outraw[8];
    buffer  out;
    buffer_init(&out, N(outraw), outraw);
    /* auth obligatoria (hay usuarios) y se ofreció user/pass -> se elige 0x02. */
    uint8_t chosen = fill_negotiation_reply(&p, &out, true);

    ck_assert_uint_eq(0x02, chosen);
    ck_assert_uint_eq(0x05, buffer_read(&out));
    ck_assert_uint_eq(0x02, buffer_read(&out));
}
END_TEST

START_TEST(test_neg_reply_falls_back_to_noauth)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);
    uint8_t inraw[32];
    buffer  in;
    buffer_init(&in, N(inraw), inraw);
    uint8_t msg[] = {0x05, 0x01, 0x00}; /* only no-auth */
    feed_bytes(&p, &in, msg, N(msg));

    uint8_t outraw[8];
    buffer  out;
    buffer_init(&out, N(outraw), outraw);
    /* sin usuarios configurados (auth no requerida) se acepta no-auth. */
    uint8_t chosen = fill_negotiation_reply(&p, &out, false);

    ck_assert_uint_eq(0x00, chosen);
    ck_assert_uint_eq(0x05, buffer_read(&out));
    ck_assert_uint_eq(0x00, buffer_read(&out));
}
END_TEST

START_TEST(test_neg_reply_no_acceptable_methods)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);
    uint8_t inraw[32];
    buffer  in;
    buffer_init(&in, N(inraw), inraw);
    uint8_t msg[] = {0x05, 0x01, 0x03}; /* only GSSAPI (unsupported) */
    feed_bytes(&p, &in, msg, N(msg));

    uint8_t outraw[8];
    buffer  out;
    buffer_init(&out, N(outraw), outraw);
    uint8_t chosen = fill_negotiation_reply(&p, &out, false);

    ck_assert_uint_eq(0xFF, chosen);
    ck_assert_uint_eq(0x05, buffer_read(&out));
    ck_assert_uint_eq(0xFF, buffer_read(&out));
}
END_TEST

/* Con usuarios configurados (auth obligatoria) un cliente que sólo ofrece
 * no-auth no puede saltear la autenticación: se rechaza con 0xFF. */
START_TEST(test_neg_reply_requires_auth_rejects_noauth)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);
    uint8_t inraw[32];
    buffer  in;
    buffer_init(&in, N(inraw), inraw);
    uint8_t msg[] = {0x05, 0x01, 0x00}; /* only no-auth */
    feed_bytes(&p, &in, msg, N(msg));

    uint8_t outraw[8];
    buffer  out;
    buffer_init(&out, N(outraw), outraw);
    uint8_t chosen = fill_negotiation_reply(&p, &out, true);

    ck_assert_uint_eq(0xFF, chosen);
}
END_TEST

/* Sin usuarios configurados, ofrecer sólo user/pass no tiene salida (nadie puede
 * autenticarse): se rechaza con 0xFF en vez de quedar colgado. */
START_TEST(test_neg_reply_no_users_rejects_userpass)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);
    uint8_t inraw[32];
    buffer  in;
    buffer_init(&in, N(inraw), inraw);
    uint8_t msg[] = {0x05, 0x01, 0x02}; /* only user/pass */
    feed_bytes(&p, &in, msg, N(msg));

    uint8_t outraw[8];
    buffer  out;
    buffer_init(&out, N(outraw), outraw);
    uint8_t chosen = fill_negotiation_reply(&p, &out, false);

    ck_assert_uint_eq(0xFF, chosen);
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("negotiation");
    TCase *tc = tcase_create("negotiation");

    tcase_add_test(tc, test_neg_noauth_happy);
    tcase_add_test(tc, test_neg_userpass_happy);
    tcase_add_test(tc, test_neg_wrong_version);
    tcase_add_test(tc, test_neg_split_feed);
    tcase_add_test(tc, test_neg_reply_prefers_userpass);
    tcase_add_test(tc, test_neg_reply_falls_back_to_noauth);
    tcase_add_test(tc, test_neg_reply_no_acceptable_methods);
    tcase_add_test(tc, test_neg_reply_requires_auth_rejects_noauth);
    tcase_add_test(tc, test_neg_reply_no_users_rejects_userpass);
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
