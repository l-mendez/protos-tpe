#ifndef RUNTIME_CONFIG_H_socks5_runtime_config
#define RUNTIME_CONFIG_H_socks5_runtime_config

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    RUNTIME_CONFIG_OK = 0,
    RUNTIME_CONFIG_NOT_FOUND,
    RUNTIME_CONFIG_INVALID,
} runtime_config_result;

void
runtime_config_init(bool disectors_enabled);

bool
runtime_config_disectors_enabled(void);

unsigned
runtime_config_handshake_timeout_seconds(void);

unsigned
runtime_config_relay_idle_timeout_seconds(void);

bool
runtime_config_get(const char *key, char *dst, size_t cap);

runtime_config_result
runtime_config_set(const char *key, const char *value);

bool
runtime_config_format_list(char *dst, size_t cap);

#endif
