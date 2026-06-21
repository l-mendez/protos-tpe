#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "buffer.h"

/* The request parser lives in src/server, outside the shared archive; include
 * the unit directly (buffer.h via -Isrc/shared). */
#include "../src/server/request.c"

#define N(x) (sizeof(x) / sizeof((x)[0]))

static req_state feed_bytes(struct socks5_request *p, buffer *b, const uint8_t *bytes, size_t len)
{
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    ck_assert_uint_ge(space, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
    return request_parser_feed(p, b);
}

START_TEST(test_req_ipv4_connect)
{
    struct socks5_request p;
    request_parser_init(&p);

    uint8_t raw[64];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);

    /* VER CMD RSV ATYP=IPv4 127.0.0.1 port=80 (0x0050) */
    uint8_t msg[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};
    req_state st = feed_bytes(&p, &buf, msg, N(msg));

    ck_assert_int_eq(REQ_DONE, st);
    ck_assert(request_done(&p));
    ck_assert_uint_eq(0x01, p.cmd);
    ck_assert_uint_eq(0x01, p.atyp);
    ck_assert_uint_eq(4, p.addr_len);
    ck_assert_uint_eq(127, p.dst_addr[0]);
    ck_assert_uint_eq(1, p.dst_addr[3]);
    ck_assert_uint_eq(80, p.dst_port);
}
END_TEST

START_TEST(test_req_ipv6_connect)
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

    ck_assert_int_eq(REQ_DONE, st);
    ck_assert_uint_eq(0x04, p.atyp);
    ck_assert_uint_eq(16, p.addr_len);
    ck_assert_uint_eq(1, p.dst_addr[15]);
    ck_assert_uint_eq(443, p.dst_port);
}
END_TEST

START_TEST(test_req_domain_connect)
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

    ck_assert_int_eq(REQ_DONE, st);
    ck_assert_uint_eq(0x03, p.atyp);
    ck_assert_uint_eq(11, p.addr_len);
    ck_assert_int_eq(0, memcmp(p.dst_addr, "example.com", 11));
    ck_assert_uint_eq(443, p.dst_port);
}
END_TEST

/* Partial reads: a domain request delivered one byte per feed (split between the
 * length byte and the name, and between the two port bytes) must parse the same. */
START_TEST(test_req_domain_split_feed)
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
            ck_assert_int_ne(REQ_DONE, st);
            ck_assert_int_ne(REQ_ERROR, st);
        }
    }
    ck_assert_int_eq(REQ_DONE, st);
    ck_assert_uint_eq(0x03, p.atyp);
    ck_assert_int_eq(0, memcmp(p.dst_addr, "example.com", 11));
    ck_assert_uint_eq(443, p.dst_port);
}
END_TEST

START_TEST(test_req_bad_version)
{
    struct socks5_request p;
    request_parser_init(&p);
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);
    uint8_t msg[] = {0x04, 0x01, 0x00, 0x01};
    ck_assert_int_eq(REQ_ERROR, feed_bytes(&p, &buf, msg, N(msg)));
}
END_TEST

START_TEST(test_req_bad_rsv)
{
    struct socks5_request p;
    request_parser_init(&p);
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);
    uint8_t msg[] = {0x05, 0x01, 0xFF, 0x01}; /* RSV must be 0x00 */
    ck_assert_int_eq(REQ_ERROR, feed_bytes(&p, &buf, msg, N(msg)));
}
END_TEST

START_TEST(test_req_unsupported_atyp)
{
    struct socks5_request p;
    request_parser_init(&p);
    uint8_t raw[16];
    buffer  buf;
    buffer_init(&buf, N(raw), raw);
    uint8_t msg[] = {0x05, 0x01, 0x00, 0x09}; /* ATYP 0x09 unsupported */
    ck_assert_int_eq(REQ_ERROR, feed_bytes(&p, &buf, msg, N(msg)));
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("request");
    TCase *tc = tcase_create("request");

    tcase_add_test(tc, test_req_ipv4_connect);
    tcase_add_test(tc, test_req_ipv6_connect);
    tcase_add_test(tc, test_req_domain_connect);
    tcase_add_test(tc, test_req_domain_split_feed);
    tcase_add_test(tc, test_req_bad_version);
    tcase_add_test(tc, test_req_bad_rsv);
    tcase_add_test(tc, test_req_unsupported_atyp);
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
