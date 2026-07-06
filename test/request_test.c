#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "test_assert.h"

#include "buffer.h"

/* The request parser lives in src/server, outside the shared archive; include
 * the unit directly (buffer.h via -Isrc/shared). */
#include "../src/server/request.c"

#define N(x) (sizeof(x) / sizeof((x)[0]))

static req_state feed_bytes(struct socks5_request *p, buffer *b, const uint8_t *bytes, size_t len)
{
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    assert_uint_ge(space, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
    return request_parser_feed(p, b);
}

static void
test_req_ipv4_connect(void)
{
    struct socks5_request p;
    request_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    /* VER CMD RSV ATYP=IPv4 127.0.0.1 port=80 (0x0050) */
    uint8_t msg[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};
    req_state st = feed_bytes(&p, &buf, msg, N(msg));

    assert_int_eq(REQ_DONE, st);
    assert(request_done(&p));
    assert_uint_eq(0x01, p.cmd);
    assert_uint_eq(0x01, p.atyp);
    assert_uint_eq(4, p.addr_len);
    assert_uint_eq(127, p.dst_addr[0]);
    assert_uint_eq(1, p.dst_addr[3]);
    assert_uint_eq(80, p.dst_port);
}

static void
test_req_ipv6_connect(void)
{
    struct socks5_request p;
    request_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    /* ATYP=IPv6 ::1 port=443 (0x01BB) */
    uint8_t msg[] = {0x05, 0x01, 0x00, 0x04,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                     0x01, 0xBB};
    req_state st = feed_bytes(&p, &buf, msg, N(msg));

    assert_int_eq(REQ_DONE, st);
    assert_uint_eq(0x04, p.atyp);
    assert_uint_eq(16, p.addr_len);
    assert_uint_eq(1, p.dst_addr[15]);
    assert_uint_eq(443, p.dst_port);
}

static void
test_req_domain_connect(void)
{
    struct socks5_request p;
    request_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    /* ATYP=domain len=11 "example.com" port=443 */
    uint8_t msg[] = {0x05, 0x01, 0x00, 0x03, 0x0B,
                     'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
                     0x01, 0xBB};
    req_state st = feed_bytes(&p, &buf, msg, N(msg));

    assert_int_eq(REQ_DONE, st);
    assert_uint_eq(0x03, p.atyp);
    assert_uint_eq(11, p.addr_len);
    assert_int_eq(0, memcmp(p.dst_addr, "example.com", 11));
    assert_uint_eq(443, p.dst_port);
}

/* Partial reads: a domain request delivered one byte per feed (split between the
 * length byte and the name, and between the two port bytes) must parse the same. */
static void
test_req_domain_split_feed(void)
{
    struct socks5_request p;
    request_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    uint8_t msg[] = {0x05, 0x01, 0x00, 0x03, 0x0B,
                     'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
                     0x01, 0xBB};
    req_state st = REQ_VER;
    for (size_t i = 0; i < N(msg); i++) {
        st = feed_bytes(&p, &buf, &msg[i], 1);
        if (i < N(msg) - 1) {
            assert_int_ne(REQ_DONE, st);
            assert_int_ne(REQ_ERROR, st);
        }
    }
    assert_int_eq(REQ_DONE, st);
    assert_uint_eq(0x03, p.atyp);
    assert_int_eq(0, memcmp(p.dst_addr, "example.com", 11));
    assert_uint_eq(443, p.dst_port);
}

static void
test_req_bad_version(void)
{
    struct socks5_request p;
    request_parser_init(&p);
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);
    uint8_t msg[] = {0x04, 0x01, 0x00, 0x01};
    assert_int_eq(REQ_ERROR, feed_bytes(&p, &buf, msg, N(msg)));
}

static void
test_req_bad_rsv(void)
{
    struct socks5_request p;
    request_parser_init(&p);
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);
    uint8_t msg[] = {0x05, 0x01, 0xFF, 0x01}; /* RSV must be 0x00 */
    assert_int_eq(REQ_ERROR, feed_bytes(&p, &buf, msg, N(msg)));
}

static void
test_req_unsupported_atyp(void)
{
    struct socks5_request p;
    request_parser_init(&p);
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);
    uint8_t msg[] = {0x05, 0x01, 0x00, 0x09}; /* ATYP 0x09 unsupported */
    assert_int_eq(REQ_ERROR, feed_bytes(&p, &buf, msg, N(msg)));
}

static void
test_req_reply_format(void)
{
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    fill_request_reply(&buf, SOCKS5_REP_CMD_NOT_SUPPORTED, SOCKS5_ATYP_IPV4);

    /* VER REP RSV ATYP=IPv4 BND.ADDR(4)=0 BND.PORT(2)=0 -> 10 bytes */
    uint8_t expected[] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < N(expected); i++) {
        assert(buffer_can_read(&buf));
        assert_uint_eq(expected[i], buffer_read(&buf));
    }
    assert(!buffer_can_read(&buf));
}

static void
test_req_reply_format_ipv6(void)
{
    uint8_t raw[32];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    fill_request_reply(&buf, SOCKS5_REP_SUCCESS, SOCKS5_ATYP_IPV6);

    uint8_t expected[22] = {0x05, 0x00, 0x00, 0x04};
    for (size_t i = 0; i < N(expected); i++) {
        assert(buffer_can_read(&buf));
        assert_uint_eq(expected[i], buffer_read(&buf));
    }
    assert(!buffer_can_read(&buf));
}

static void
test_req_reply_addr_ipv4(void)
{
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(8080),
    };
    addr.sin_addr.s_addr = htonl(0x7F000001);

    assert(fill_request_reply_addr(&buf, SOCKS5_REP_SUCCESS,
                                      (const struct sockaddr *)&addr));

    uint8_t expected[] = {
        0x05, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4,
        127, 0, 0, 1,
        0x1F, 0x90
    };
    for (size_t i = 0; i < N(expected); i++) {
        assert(buffer_can_read(&buf));
        assert_uint_eq(expected[i], buffer_read(&buf));
    }
    assert(!buffer_can_read(&buf));
}

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_req_ipv4_connect, "test_req_ipv4_connect");
    failures += test_run_case(test_req_ipv6_connect, "test_req_ipv6_connect");
    failures += test_run_case(test_req_domain_connect, "test_req_domain_connect");
    failures += test_run_case(test_req_domain_split_feed, "test_req_domain_split_feed");
    failures += test_run_case(test_req_bad_version, "test_req_bad_version");
    failures += test_run_case(test_req_bad_rsv, "test_req_bad_rsv");
    failures += test_run_case(test_req_unsupported_atyp, "test_req_unsupported_atyp");
    failures += test_run_case(test_req_reply_format, "test_req_reply_format");
    failures += test_run_case(test_req_reply_format_ipv6, "test_req_reply_format_ipv6");
    failures += test_run_case(test_req_reply_addr_ipv4, "test_req_reply_addr_ipv4");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
