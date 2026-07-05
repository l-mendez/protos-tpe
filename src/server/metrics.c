#include "metrics.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static struct {
    uint64_t socks_connections_total;
    uint64_t socks_connections_current;
    uint64_t bytes_client_to_origin;
    uint64_t bytes_origin_to_client;
    uint64_t auth_success_total;
    uint64_t auth_failure_total;
    uint64_t connect_success_total;
    uint64_t connect_failure_total;
} metrics;

void metrics_reset(void)
{
    memset(&metrics, 0, sizeof(metrics));
}

void metrics_socks_connection_opened(void)
{
    metrics.socks_connections_total++;
    metrics.socks_connections_current++;
}

void metrics_socks_connection_closed(void)
{
    if (metrics.socks_connections_current > 0) {
        metrics.socks_connections_current--;
    }
}

void metrics_auth_success(void)
{
    metrics.auth_success_total++;
}

void metrics_auth_failure(void)
{
    metrics.auth_failure_total++;
}

void metrics_connect_success(void)
{
    metrics.connect_success_total++;
}

void metrics_connect_failure(void)
{
    metrics.connect_failure_total++;
}

void metrics_add_client_to_origin_bytes(uint64_t n)
{
    metrics.bytes_client_to_origin += n;
}

void metrics_add_origin_to_client_bytes(uint64_t n)
{
    metrics.bytes_origin_to_client += n;
}

bool metrics_format(char *dst, size_t cap)
{
    uint64_t total;
    int written;

    if (dst == NULL || cap == 0) {
        return false;
    }
    total = metrics.bytes_client_to_origin + metrics.bytes_origin_to_client;
    written = snprintf(dst, cap,
                       "socks_connections_total=%" PRIu64 " "
                       "socks_connections_current=%" PRIu64 " "
                       "bytes_client_to_origin=%" PRIu64 " "
                       "bytes_origin_to_client=%" PRIu64 " "
                       "bytes_total=%" PRIu64 " "
                       "auth_success_total=%" PRIu64 " "
                       "auth_failure_total=%" PRIu64 " "
                       "connect_success_total=%" PRIu64 " "
                       "connect_failure_total=%" PRIu64,
                       metrics.socks_connections_total,
                       metrics.socks_connections_current,
                       metrics.bytes_client_to_origin,
                       metrics.bytes_origin_to_client,
                       total,
                       metrics.auth_success_total,
                       metrics.auth_failure_total,
                       metrics.connect_success_total,
                       metrics.connect_failure_total);
    return written >= 0 && (size_t)written < cap;
}
