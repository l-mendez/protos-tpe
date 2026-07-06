#include <stdlib.h>

#include "test_assert.h"

/* metrics vive en src/server, fuera del archivo compartido contra el que linkean
 * los tests, así que se incluye la unidad directamente (mismo enfoque que
 * auth_test / negotiation_test) para poder resetear sus estáticos entre casos. */
#include "../src/server/metrics.c"

/* Deja los contadores estáticos en cero antes de cada caso: los tests corren en
 * procesos forkeados por Check, pero resetear explícito mantiene los casos
 * independientes aunque se ejecuten en el mismo proceso (CK_NOFORK). */
static void reset_metrics(void)
{
    historical_connections     = 0;
    concurrent_connections     = 0;
    max_concurrent_connections = 0;
    bytes_client_to_origin     = 0;
    bytes_origin_to_client     = 0;
}

START_TEST(test_metrics_initial)
{
    reset_metrics();
    struct metrics_snapshot s = metrics_get();
    ck_assert_uint_eq(0, s.historical_connections);
    ck_assert_uint_eq(0, s.concurrent_connections);
    ck_assert_uint_eq(0, s.max_concurrent_connections);
    ck_assert_uint_eq(0, s.total_bytes);
}
END_TEST

START_TEST(test_metrics_connections_and_peak)
{
    reset_metrics();

    metrics_connection_opened(); /* concurrent=1, hist=1, max=1 */
    metrics_connection_opened(); /* concurrent=2, hist=2, max=2 */
    metrics_connection_opened(); /* concurrent=3, hist=3, max=3 */

    struct metrics_snapshot s = metrics_get();
    ck_assert_uint_eq(3, s.historical_connections);
    ck_assert_uint_eq(3, s.concurrent_connections);
    ck_assert_uint_eq(3, s.max_concurrent_connections);

    metrics_connection_closed(); /* concurrent=2 */
    metrics_connection_closed(); /* concurrent=1 */

    s = metrics_get();
    /* histórico y pico no bajan; concurrentes sí */
    ck_assert_uint_eq(3, s.historical_connections);
    ck_assert_uint_eq(1, s.concurrent_connections);
    ck_assert_uint_eq(3, s.max_concurrent_connections);

    metrics_connection_opened(); /* concurrent=2, hist=4, max sigue 3 */
    s = metrics_get();
    ck_assert_uint_eq(4, s.historical_connections);
    ck_assert_uint_eq(2, s.concurrent_connections);
    ck_assert_uint_eq(3, s.max_concurrent_connections);
}
END_TEST

START_TEST(test_metrics_close_never_underflows)
{
    reset_metrics();
    metrics_connection_closed(); /* sin aperturas previas: no debe underflowear */
    struct metrics_snapshot s = metrics_get();
    ck_assert_uint_eq(0, s.concurrent_connections);
}
END_TEST

START_TEST(test_metrics_bytes)
{
    reset_metrics();
    metrics_bytes_client_to_origin(100);
    metrics_bytes_client_to_origin(50);
    metrics_bytes_origin_to_client(400);

    struct metrics_snapshot s = metrics_get();
    ck_assert_uint_eq(150, s.bytes_client_to_origin);
    ck_assert_uint_eq(400, s.bytes_origin_to_client);
    ck_assert_uint_eq(550, s.total_bytes);
}
END_TEST

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_metrics_initial, "test_metrics_initial");
    failures += test_run_case(test_metrics_connections_and_peak, "test_metrics_connections_and_peak");
    failures += test_run_case(test_metrics_close_never_underflows, "test_metrics_close_never_underflows");
    failures += test_run_case(test_metrics_bytes, "test_metrics_bytes");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
