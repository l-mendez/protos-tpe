#ifndef STRESS_HELPERS_H
#define STRESS_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct stress_metrics {
    uint64_t historical_connections;
    size_t active_connections;
    size_t max_active_connections;
    uint64_t bytes_client_to_origin;
    uint64_t bytes_origin_to_client;
    uint64_t total_bytes;
    size_t users_count;
};

int stress_build_negotiation(uint8_t *dst, size_t cap);
int stress_build_auth(uint8_t *dst, size_t cap, const char *user, const char *pass);
int stress_build_connect_ipv4(uint8_t *dst, size_t cap, uint32_t addr_host_order,
                              uint16_t port_host_order);
bool stress_validate_negotiation(const uint8_t reply[2]);
bool stress_validate_auth(const uint8_t reply[2]);
bool stress_validate_connect_ipv4(const uint8_t reply[10]);

bool stress_parse_metrics(const char *response, struct stress_metrics *out);
double stress_median(double *values, size_t count);
double stress_percentile(double *values, size_t count, double percentile);
bool stress_json_string(FILE *out, const char *value);

#endif
