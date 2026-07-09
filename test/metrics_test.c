#include <stdlib.h>

#include <check.h>

/* metrics vive en src/server, fuera del archivo compartido contra el que linkean
 * los tests, así que se incluye la unidad directamente (mismo enfoque que
 * auth_test / negotiation_test). Cada caso usa su propia instancia, por lo que
 * quedan independientes sin necesidad de resetear estado global. */
#include "../src/server/metrics.c"

START_TEST(test_metrics_initial)
{
    struct Metrics m;
    metrics_init(&m);
    ck_assert_uint_eq(0, m.historical_connections);
    ck_assert_uint_eq(0, m.active_connections);
    ck_assert_uint_eq(0, m.max_active_connections);
    ck_assert_uint_eq(0, m.bytes_client_to_origin);
    ck_assert_uint_eq(0, m.bytes_origin_to_client);
}
END_TEST

START_TEST(test_metrics_connections_and_peak)
{
    struct Metrics m;
    metrics_init(&m);

    metrics_connection_opened(&m); /* concurrent=1, hist=1, max=1 */
    metrics_connection_opened(&m); /* concurrent=2, hist=2, max=2 */
    metrics_connection_opened(&m); /* concurrent=3, hist=3, max=3 */

    ck_assert_uint_eq(3, m.historical_connections);
    ck_assert_uint_eq(3, m.active_connections);
    ck_assert_uint_eq(3, m.max_active_connections);

    metrics_connection_closed(&m); /* concurrent=2 */
    metrics_connection_closed(&m); /* concurrent=1 */

    /* histórico y pico no bajan; concurrentes sí */
    ck_assert_uint_eq(3, m.historical_connections);
    ck_assert_uint_eq(1, m.active_connections);
    ck_assert_uint_eq(3, m.max_active_connections);

    metrics_connection_opened(&m); /* concurrent=2, hist=4, max sigue 3 */
    ck_assert_uint_eq(4, m.historical_connections);
    ck_assert_uint_eq(2, m.active_connections);
    ck_assert_uint_eq(3, m.max_active_connections);
}
END_TEST

START_TEST(test_metrics_close_never_underflows)
{
    struct Metrics m;
    metrics_init(&m);
    metrics_connection_closed(&m); /* sin aperturas previas: no debe underflowear */
    ck_assert_uint_eq(0, m.active_connections);
}
END_TEST

START_TEST(test_metrics_bytes)
{
    struct Metrics m;
    metrics_init(&m);
    metrics_bytes_client_to_origin(&m, 100);
    metrics_bytes_client_to_origin(&m, 50);
    metrics_bytes_origin_to_client(&m, 400);

    ck_assert_uint_eq(150, m.bytes_client_to_origin);
    ck_assert_uint_eq(400, m.bytes_origin_to_client);
    ck_assert_uint_eq(550, m.bytes_client_to_origin + m.bytes_origin_to_client);
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("metrics");
    TCase *tc = tcase_create("metrics");

    tcase_add_test(tc, test_metrics_initial);
    tcase_add_test(tc, test_metrics_connections_and_peak);
    tcase_add_test(tc, test_metrics_close_never_underflows);
    tcase_add_test(tc, test_metrics_bytes);
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
