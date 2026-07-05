#include "runtime_config.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_HANDSHAKE_TIMEOUT 60U
#define DEFAULT_RELAY_IDLE_TIMEOUT 900U
#define MAX_HANDSHAKE_TIMEOUT 3600U
#define MAX_RELAY_IDLE_TIMEOUT 86400U

static struct {
    bool initialized;
    bool disectors_enabled;
    unsigned handshake_timeout_seconds;
    unsigned relay_idle_timeout_seconds;
} config;

static void ensure_initialized(void)
{
    if (!config.initialized) {
        runtime_config_init(true);
    }
}

static bool parse_bool(const char *value, bool *out)
{
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
        *out = true;
        return true;
    }
    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool parse_uint_range(const char *value, unsigned min, unsigned max, unsigned *out)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0' || errno == ERANGE ||
        parsed < min || parsed > max || parsed > UINT_MAX) {
        return false;
    }
    *out = (unsigned)parsed;
    return true;
}

void runtime_config_init(bool disectors_enabled)
{
    config.initialized = true;
    config.disectors_enabled = disectors_enabled;
    config.handshake_timeout_seconds = DEFAULT_HANDSHAKE_TIMEOUT;
    config.relay_idle_timeout_seconds = DEFAULT_RELAY_IDLE_TIMEOUT;
}

bool runtime_config_disectors_enabled(void)
{
    ensure_initialized();
    return config.disectors_enabled;
}

unsigned runtime_config_handshake_timeout_seconds(void)
{
    ensure_initialized();
    return config.handshake_timeout_seconds;
}

unsigned runtime_config_relay_idle_timeout_seconds(void)
{
    ensure_initialized();
    return config.relay_idle_timeout_seconds;
}

bool runtime_config_get(const char *key, char *dst, size_t cap)
{
    int written;

    if (key == NULL || dst == NULL || cap == 0) {
        return false;
    }
    ensure_initialized();
    if (strcmp(key, "disectors_enabled") == 0) {
        written = snprintf(dst, cap, "%s", config.disectors_enabled ? "true" : "false");
    } else if (strcmp(key, "handshake_timeout_seconds") == 0) {
        written = snprintf(dst, cap, "%u", config.handshake_timeout_seconds);
    } else if (strcmp(key, "relay_idle_timeout_seconds") == 0) {
        written = snprintf(dst, cap, "%u", config.relay_idle_timeout_seconds);
    } else {
        return false;
    }
    return written >= 0 && (size_t)written < cap;
}

runtime_config_result runtime_config_set(const char *key, const char *value)
{
    bool b;
    unsigned n;

    if (key == NULL || value == NULL) {
        return RUNTIME_CONFIG_INVALID;
    }
    ensure_initialized();
    if (strcmp(key, "disectors_enabled") == 0) {
        if (!parse_bool(value, &b)) {
            return RUNTIME_CONFIG_INVALID;
        }
        config.disectors_enabled = b;
        return RUNTIME_CONFIG_OK;
    }
    if (strcmp(key, "handshake_timeout_seconds") == 0) {
        if (!parse_uint_range(value, 1, MAX_HANDSHAKE_TIMEOUT, &n)) {
            return RUNTIME_CONFIG_INVALID;
        }
        config.handshake_timeout_seconds = n;
        return RUNTIME_CONFIG_OK;
    }
    if (strcmp(key, "relay_idle_timeout_seconds") == 0) {
        if (!parse_uint_range(value, 1, MAX_RELAY_IDLE_TIMEOUT, &n)) {
            return RUNTIME_CONFIG_INVALID;
        }
        config.relay_idle_timeout_seconds = n;
        return RUNTIME_CONFIG_OK;
    }
    return RUNTIME_CONFIG_NOT_FOUND;
}

bool runtime_config_format_list(char *dst, size_t cap)
{
    int written;

    if (dst == NULL || cap == 0) {
        return false;
    }
    ensure_initialized();
    written = snprintf(dst, cap,
                       "disectors_enabled=%s handshake_timeout_seconds=%u relay_idle_timeout_seconds=%u",
                       config.disectors_enabled ? "true" : "false",
                       config.handshake_timeout_seconds,
                       config.relay_idle_timeout_seconds);
    return written >= 0 && (size_t)written < cap;
}
