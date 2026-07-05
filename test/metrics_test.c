#include <stdlib.h>
#include <check.h>

#include "../src/server/metrics.h"
#include "../src/server/metrics.c"

START_TEST(test_metrics_counters_and_format)
{
    char payload[512];

    metrics_reset();
    metrics_socks_connection_opened();
    metrics_socks_connection_opened();
    metrics_socks_connection_closed();
    metrics_auth_success();
    metrics_auth_failure();
    metrics_connect_success();
    metrics_connect_failure();
    metrics_add_client_to_origin_bytes(12);
    metrics_add_origin_to_client_bytes(30);

    ck_assert(metrics_format(payload, sizeof(payload)));
    ck_assert_str_eq("socks_connections_total=2 socks_connections_current=1 "
                     "bytes_client_to_origin=12 bytes_origin_to_client=30 "
                     "bytes_total=42 auth_success_total=1 auth_failure_total=1 "
                     "connect_success_total=1 connect_failure_total=1",
                     payload);
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("metrics");
    TCase *tc = tcase_create("metrics");
    tcase_add_test(tc, test_metrics_counters_and_format);
    suite_add_tcase(s, tc);
    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
