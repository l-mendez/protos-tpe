#include "stress_helpers.h"

#include <stdlib.h>
#include <string.h>

int stress_build_negotiation(uint8_t *dst, size_t cap)
{
    if (dst == NULL || cap < 3) {
        return -1;
    }
    dst[0] = 0x05;
    dst[1] = 0x01;
    dst[2] = 0x02;
    return 3;
}

int stress_build_auth(uint8_t *dst, size_t cap, const char *user, const char *pass)
{
    if (dst == NULL || user == NULL || pass == NULL) {
        return -1;
    }
    size_t user_len = strlen(user);
    size_t pass_len = strlen(pass);
    size_t len = 3 + user_len + pass_len;
    if (user_len == 0 || user_len > UINT8_MAX || pass_len == 0 ||
        pass_len > UINT8_MAX || cap < len) {
        return -1;
    }
    dst[0] = 0x01;
    dst[1] = (uint8_t)user_len;
    memcpy(dst + 2, user, user_len);
    dst[2 + user_len] = (uint8_t)pass_len;
    memcpy(dst + 3 + user_len, pass, pass_len);
    return (int)len;
}

int stress_build_connect_ipv4(uint8_t *dst, size_t cap, uint32_t addr,
                              uint16_t port)
{
    if (dst == NULL || cap < 10) {
        return -1;
    }
    dst[0] = 0x05;
    dst[1] = 0x01;
    dst[2] = 0x00;
    dst[3] = 0x01;
    dst[4] = (uint8_t)(addr >> 24);
    dst[5] = (uint8_t)(addr >> 16);
    dst[6] = (uint8_t)(addr >> 8);
    dst[7] = (uint8_t)addr;
    dst[8] = (uint8_t)(port >> 8);
    dst[9] = (uint8_t)port;
    return 10;
}

bool stress_validate_negotiation(const uint8_t reply[2])
{
    return reply != NULL && reply[0] == 0x05 && reply[1] == 0x02;
}

bool stress_validate_auth(const uint8_t reply[2])
{
    return reply != NULL && reply[0] == 0x01 && reply[1] == 0x00;
}

bool stress_validate_connect_ipv4(const uint8_t reply[10])
{
    return reply != NULL && reply[0] == 0x05 && reply[1] == 0x00 &&
           reply[2] == 0x00 && reply[3] == 0x01;
}

static bool parse_u64(const char *line, const char *key, uint64_t *out)
{
    size_t key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != ' ') {
        return false;
    }
    char *end = NULL;
    unsigned long long value = strtoull(line + key_len + 1, &end, 10);
    if (end == line + key_len + 1 || *end != '\0') {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

bool stress_parse_metrics(const char *response, struct stress_metrics *out)
{
    if (response == NULL || out == NULL || strncmp(response, "+OK 7\n", 6) != 0) {
        return false;
    }
    struct stress_metrics parsed = {0};
    unsigned seen = 0;
    const char *p = response + 6;
    for (unsigned i = 0; i < 7; i++) {
        const char *end = strchr(p, '\n');
        if (end == NULL || (size_t)(end - p) >= 128) {
            return false;
        }
        char line[128];
        memcpy(line, p, (size_t)(end - p));
        line[end - p] = '\0';

        uint64_t value;
        unsigned bit;
        if (parse_u64(line, "active_connections", &value)) {
            parsed.active_connections = (size_t)value;
            bit = 1u << 0;
        } else if (parse_u64(line, "historical_connections", &value)) {
            parsed.historical_connections = value;
            bit = 1u << 1;
        } else if (parse_u64(line, "max_active_connections", &value)) {
            parsed.max_active_connections = (size_t)value;
            bit = 1u << 2;
        } else if (parse_u64(line, "bytes_client_to_origin", &value)) {
            parsed.bytes_client_to_origin = value;
            bit = 1u << 3;
        } else if (parse_u64(line, "bytes_origin_to_client", &value)) {
            parsed.bytes_origin_to_client = value;
            bit = 1u << 4;
        } else if (parse_u64(line, "total_bytes", &value)) {
            parsed.total_bytes = value;
            bit = 1u << 5;
        } else if (parse_u64(line, "users_count", &value)) {
            parsed.users_count = (size_t)value;
            bit = 1u << 6;
        } else {
            return false;
        }
        if ((seen & bit) != 0) {
            return false;
        }
        seen |= bit;
        p = end + 1;
    }
    if (seen != 0x7fu || *p != '\0') {
        return false;
    }
    *out = parsed;
    return true;
}

static int compare_double(const void *a, const void *b)
{
    double av = *(const double *)a;
    double bv = *(const double *)b;
    return (av > bv) - (av < bv);
}

double stress_median(double *values, size_t count)
{
    if (values == NULL || count == 0) {
        return 0.0;
    }
    qsort(values, count, sizeof(*values), compare_double);
    if ((count & 1u) != 0) {
        return values[count / 2];
    }
    return (values[count / 2 - 1] + values[count / 2]) / 2.0;
}

double stress_percentile(double *values, size_t count, double percentile)
{
    if (values == NULL || count == 0 || percentile <= 0.0 || percentile > 1.0) {
        return 0.0;
    }
    qsort(values, count, sizeof(*values), compare_double);
    size_t rank = (size_t)(percentile * (double)count);
    if ((double)rank < percentile * (double)count) {
        rank++;
    }
    if (rank == 0) {
        rank = 1;
    }
    return values[rank - 1];
}

bool stress_json_string(FILE *out, const char *value)
{
    if (out == NULL || value == NULL || fputc('"', out) == EOF) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        int rc;
        switch (*p) {
            case '"': rc = fputs("\\\"", out); break;
            case '\\': rc = fputs("\\\\", out); break;
            case '\b': rc = fputs("\\b", out); break;
            case '\f': rc = fputs("\\f", out); break;
            case '\n': rc = fputs("\\n", out); break;
            case '\r': rc = fputs("\\r", out); break;
            case '\t': rc = fputs("\\t", out); break;
            default:
                rc = *p < 0x20 ? fprintf(out, "\\u%04x", *p) : fputc(*p, out);
                break;
        }
        if (rc < 0) {
            return false;
        }
    }
    return fputc('"', out) != EOF;
}
