#include "metrics.h"

/* Estado global de métricas. Volátil por diseño (req 6): si el servidor se
 * reinicia, las estadísticas pueden perderse. Se accede sólo desde el hilo del
 * selector, así que no hace falta sincronización. */
static uint64_t historical_connections     = 0;
static size_t   concurrent_connections     = 0;
static size_t   max_concurrent_connections = 0;
static uint64_t bytes_client_to_origin     = 0;
static uint64_t bytes_origin_to_client     = 0;

void
metrics_connection_opened(void)
{
    historical_connections++;
    concurrent_connections++;
    if (concurrent_connections > max_concurrent_connections) {
        max_concurrent_connections = concurrent_connections;
    }
}

void
metrics_connection_closed(void)
{
    if (concurrent_connections > 0) {
        concurrent_connections--;
    }
}

void
metrics_bytes_client_to_origin(size_t n)
{
    bytes_client_to_origin += n;
}

void
metrics_bytes_origin_to_client(size_t n)
{
    bytes_origin_to_client += n;
}

struct metrics_snapshot
metrics_get(void)
{
    struct metrics_snapshot snap = {
        .historical_connections     = historical_connections,
        .concurrent_connections     = concurrent_connections,
        .max_concurrent_connections = max_concurrent_connections,
        .bytes_client_to_origin     = bytes_client_to_origin,
        .bytes_origin_to_client     = bytes_origin_to_client,
        .total_bytes                = bytes_client_to_origin + bytes_origin_to_client,
    };
    return snap;
}
