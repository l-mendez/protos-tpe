#include <stdlib.h>
#include <string.h>

#include "test_assert.h"

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
    assert_uint_ge(space, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
    return negotiation_parser_feed(p, b);
}

static void
test_neg_noauth_happy(void)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t   raw[32];
    buffer    buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x01, 0x00}; /* VER=5, NMETHODS=1, no-auth */
    neg_state st = feed_bytes(&p, &buf, msg, N(msg));

    assert_int_eq(NEG_DONE, st);
    assert(negotiation_done(&p));
    assert(p.has_noauth);
    assert(!p.has_userpass);
}

static void
test_neg_userpass_happy(void)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t raw[32];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x02, 0x00, 0x02}; /* offers no-auth AND user/pass */
    neg_state st = feed_bytes(&p, &buf, msg, N(msg));

    assert_int_eq(NEG_DONE, st);
    assert(p.has_noauth);
    assert(p.has_userpass);
}

static void
test_neg_wrong_version(void)
{
    struct negotiation_parser p;
    negotiation_parser_init(&p);

    uint8_t raw[32];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x04, 0x01, 0x00}; /* VER=4 -> invalid */
    neg_state st = feed_bytes(&p, &buf, msg, N(msg));

    assert_int_eq(NEG_INVALID, st);
}

/* Partial reads: the same message delivered one byte per feed must parse
 * identically. This is the core "manejar lecturas parciales" requirement. */
static void
test_neg_split_feed(void)
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
            assert_int_ne(NEG_DONE, st);
            assert_int_ne(NEG_INVALID, st);
        }
    }
    assert_int_eq(NEG_DONE, st);
    assert(p.has_userpass);
}

static void
test_neg_reply_prefers_userpass(void)
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

    assert_uint_eq(0x02, chosen);
    assert_uint_eq(0x05, buffer_read(&out));
    assert_uint_eq(0x02, buffer_read(&out));
}

static void
test_neg_reply_falls_back_to_noauth(void)
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

    assert_uint_eq(0x00, chosen);
    assert_uint_eq(0x05, buffer_read(&out));
    assert_uint_eq(0x00, buffer_read(&out));
}

static void
test_neg_reply_no_acceptable_methods(void)
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

    assert_uint_eq(0xFF, chosen);
    assert_uint_eq(0x05, buffer_read(&out));
    assert_uint_eq(0xFF, buffer_read(&out));
}

/* Con usuarios configurados (auth obligatoria) un cliente que sólo ofrece
 * no-auth no puede saltear la autenticación: se rechaza con 0xFF. */
static void
test_neg_reply_requires_auth_rejects_noauth(void)
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

    assert_uint_eq(0xFF, chosen);
}

/* Sin usuarios configurados, ofrecer sólo user/pass no tiene salida (nadie puede
 * autenticarse): se rechaza con 0xFF en vez de quedar colgado. */
static void
test_neg_reply_no_users_rejects_userpass(void)
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

    assert_uint_eq(0xFF, chosen);
}

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_neg_noauth_happy, "test_neg_noauth_happy");
    failures += test_run_case(test_neg_userpass_happy, "test_neg_userpass_happy");
    failures += test_run_case(test_neg_wrong_version, "test_neg_wrong_version");
    failures += test_run_case(test_neg_split_feed, "test_neg_split_feed");
    failures += test_run_case(test_neg_reply_prefers_userpass, "test_neg_reply_prefers_userpass");
    failures += test_run_case(test_neg_reply_falls_back_to_noauth, "test_neg_reply_falls_back_to_noauth");
    failures += test_run_case(test_neg_reply_no_acceptable_methods, "test_neg_reply_no_acceptable_methods");
    failures += test_run_case(test_neg_reply_requires_auth_rejects_noauth, "test_neg_reply_requires_auth_rejects_noauth");
    failures += test_run_case(test_neg_reply_no_users_rejects_userpass, "test_neg_reply_no_users_rejects_userpass");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
