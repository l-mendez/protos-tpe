#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "test_assert.h"

#include "netutils.h"

START_TEST (test_sockaddr_to_human_ipv4) {
    char buff[50] = {0};

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(9090),
    };
    addr.sin_addr.s_addr = htonl(0x01020304);
    const struct sockaddr *x = (const struct sockaddr *) &addr;

    ck_assert_str_eq(sockaddr_to_human(buff, sizeof(buff)/sizeof(buff[0]), x),
                     "1.2.3.4:9090");
    ck_assert_str_eq(sockaddr_to_human(buff, 5,  x), "unkn");
    ck_assert_str_eq(sockaddr_to_human(buff, 8,  x), "1.2.3.4");
    ck_assert_str_eq(sockaddr_to_human(buff, 9,  x), "1.2.3.4:");
    ck_assert_str_eq(sockaddr_to_human(buff, 10, x), "1.2.3.4:9");
    ck_assert_str_eq(sockaddr_to_human(buff, 11, x), "1.2.3.4:90");
    ck_assert_str_eq(sockaddr_to_human(buff, 12, x), "1.2.3.4:909");
    ck_assert_str_eq(sockaddr_to_human(buff, 13, x), "1.2.3.4:9090");
}
END_TEST


START_TEST (test_sockaddr_to_human_ipv6) {
    char buff[50] = {0};

    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(9090),
    };
    uint8_t *d = ((uint8_t *)&addr.sin6_addr);
    for(int i = 0; i < 16; i++) {
        d[i] = 0xFF;
    }

    const struct sockaddr *x = (const struct sockaddr *) &addr;
    ck_assert_str_eq(sockaddr_to_human(buff, 10, x), "unknown i");
    ck_assert_str_eq(sockaddr_to_human(buff, 39, x), "unknown ip:9090");
    ck_assert_str_eq(sockaddr_to_human(buff, 40, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ck_assert_str_eq(sockaddr_to_human(buff, 41, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:");
    ck_assert_str_eq(sockaddr_to_human(buff, 42, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:9");
    ck_assert_str_eq(sockaddr_to_human(buff, 43, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:90");
    ck_assert_str_eq(sockaddr_to_human(buff, 44, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:909");
    ck_assert_str_eq(sockaddr_to_human(buff, 45, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:9090");
}
END_TEST

START_TEST(test_sockaddr_get_addr_port_ipv4)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(1080),
    };
    addr.sin_addr.s_addr = htonl(0x7F000001);

    const uint8_t *addr_bytes = NULL;
    size_t         addr_len   = 0;
    uint16_t       port       = 0;
    ck_assert(sockaddr_get_addr_port((const struct sockaddr *)&addr,
                                     &addr_bytes, &addr_len, &port));
    ck_assert_uint_eq(4, addr_len);
    ck_assert_uint_eq(1080, port);
    ck_assert_uint_eq(127, addr_bytes[0]);
    ck_assert_uint_eq(1, addr_bytes[3]);
}
END_TEST

START_TEST(test_sockaddr_get_addr_port_ipv6)
{
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(9090),
    };
    uint8_t *raw = (uint8_t *)&addr.sin6_addr;
    for (int i = 0; i < 16; i++) {
        raw[i] = (uint8_t)i;
    }

    const uint8_t *addr_bytes = NULL;
    size_t         addr_len   = 0;
    uint16_t       port       = 0;
    ck_assert(sockaddr_get_addr_port((const struct sockaddr *)&addr,
                                     &addr_bytes, &addr_len, &port));
    ck_assert_uint_eq(16, addr_len);
    ck_assert_uint_eq(9090, port);
    ck_assert_uint_eq(0, addr_bytes[0]);
    ck_assert_uint_eq(15, addr_bytes[15]);
}
END_TEST

START_TEST(test_sockaddr_get_addr_port_rejects_unknown_family)
{
    struct sockaddr addr = { .sa_family = AF_UNIX };
    const uint8_t *addr_bytes = NULL;
    size_t         addr_len   = 0;
    uint16_t       port       = 0;

    ck_assert(!sockaddr_get_addr_port(&addr, &addr_bytes, &addr_len, &port));
}
END_TEST

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_sockaddr_to_human_ipv4, "test_sockaddr_to_human_ipv4");
    failures += test_run_case(test_sockaddr_to_human_ipv6, "test_sockaddr_to_human_ipv6");
    failures += test_run_case(test_sockaddr_get_addr_port_ipv4, "test_sockaddr_get_addr_port_ipv4");
    failures += test_run_case(test_sockaddr_get_addr_port_ipv6, "test_sockaddr_get_addr_port_ipv6");
    failures += test_run_case(test_sockaddr_get_addr_port_rejects_unknown_family, "test_sockaddr_get_addr_port_rejects_unknown_family");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
