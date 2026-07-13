#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../stress/stress_helpers.c"

START_TEST(test_builds_rfc1929_handshake_messages)
{
    uint8_t buf[300];
    const uint8_t negotiation[] = {0x05, 0x01, 0x02};
    const uint8_t auth[] = {0x01, 0x06, 's', 't', 'r', 'e', 's', 's',
                            0x02, 'p', 'w'};
    const uint8_t connect[] = {0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00,
                               0x01, 0x1f, 0x90};

    ck_assert_int_eq(3, stress_build_negotiation(buf, sizeof(buf)));
    ck_assert_mem_eq(buf, negotiation, sizeof(negotiation));

    ck_assert_int_eq(11, stress_build_auth(buf, sizeof(buf), "stress", "pw"));
    ck_assert_mem_eq(buf, auth, sizeof(auth));

    ck_assert_int_eq(10, stress_build_connect_ipv4(buf, sizeof(buf),
                                                  0x7f000001u, 8080));
    ck_assert_mem_eq(buf, connect, sizeof(connect));
}
END_TEST

START_TEST(test_rejects_oversized_auth_fields)
{
    char user[257];
    uint8_t buf[600];
    memset(user, 'x', sizeof(user) - 1);
    user[sizeof(user) - 1] = '\0';

    ck_assert_int_eq(-1, stress_build_auth(buf, sizeof(buf), user, "pw"));
}
END_TEST

START_TEST(test_validates_socks_replies)
{
    ck_assert(stress_validate_negotiation((uint8_t[]){0x05, 0x02}));
    ck_assert(!stress_validate_negotiation((uint8_t[]){0x05, 0xff}));
    ck_assert(stress_validate_auth((uint8_t[]){0x01, 0x00}));
    ck_assert(!stress_validate_auth((uint8_t[]){0x01, 0x01}));
    ck_assert(stress_validate_connect_ipv4(
        (uint8_t[]){0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}));
    ck_assert(!stress_validate_connect_ipv4(
        (uint8_t[]){0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}));
}
END_TEST

START_TEST(test_parses_complete_smcp_metrics_response)
{
    const char *response =
        "+OK 7\n"
        "active_connections 500\n"
        "historical_connections 501\n"
        "max_active_connections 500\n"
        "bytes_client_to_origin 1024\n"
        "bytes_origin_to_client 2048\n"
        "total_bytes 3072\n"
        "users_count 1\n";
    struct stress_metrics metrics;

    ck_assert(stress_parse_metrics(response, &metrics));
    ck_assert_uint_eq(500, metrics.active_connections);
    ck_assert_uint_eq(501, metrics.historical_connections);
    ck_assert_uint_eq(500, metrics.max_active_connections);
    ck_assert_uint_eq(1024, metrics.bytes_client_to_origin);
    ck_assert_uint_eq(2048, metrics.bytes_origin_to_client);
}
END_TEST

START_TEST(test_rejects_incomplete_smcp_metrics_response)
{
    struct stress_metrics metrics;
    ck_assert(!stress_parse_metrics("+OK 1\nactive_connections 1\n", &metrics));
}
END_TEST

START_TEST(test_computes_median)
{
    double values[] = {5.0, 1.0, 3.0, 2.0, 4.0};
    ck_assert_double_eq_tol(3.0, stress_median(values, 5), 0.0001);
}
END_TEST

START_TEST(test_json_escape_handles_control_characters)
{
    FILE *f = tmpfile();
    ck_assert_ptr_nonnull(f);
    ck_assert(stress_json_string(f, "a\"b\\c\n"));
    rewind(f);

    char out[64] = {0};
    ck_assert_int_gt((int)fread(out, 1, sizeof(out) - 1, f), 0);
    ck_assert_str_eq("\"a\\\"b\\\\c\\n\"", out);
    fclose(f);
}
END_TEST

static Suite *stress_helpers_suite(void)
{
    Suite *s = suite_create("stress_helpers");
    TCase *tc = tcase_create("core");
    tcase_add_test(tc, test_builds_rfc1929_handshake_messages);
    tcase_add_test(tc, test_rejects_oversized_auth_fields);
    tcase_add_test(tc, test_validates_socks_replies);
    tcase_add_test(tc, test_parses_complete_smcp_metrics_response);
    tcase_add_test(tc, test_rejects_incomplete_smcp_metrics_response);
    tcase_add_test(tc, test_computes_median);
    tcase_add_test(tc, test_json_escape_handles_control_characters);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    Suite *s = stress_helpers_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
