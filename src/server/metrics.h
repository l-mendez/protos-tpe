#ifndef METRICS_H_socks5_metrics
#define METRICS_H_socks5_metrics

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void
metrics_reset(void);

void
metrics_socks_connection_opened(void);

void
metrics_socks_connection_closed(void);

void
metrics_auth_success(void);

void
metrics_auth_failure(void);

void
metrics_connect_success(void);

void
metrics_connect_failure(void);

void
metrics_add_client_to_origin_bytes(uint64_t n);

void
metrics_add_origin_to_client_bytes(uint64_t n);

bool
metrics_format(char *dst, size_t cap);

#endif
