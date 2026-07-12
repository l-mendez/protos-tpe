#include "config.h"

void
config_init(struct Config *c, uint32_t max_connections_hard)
{
    c->conn_timeout         = CONFIG_CONN_TIMEOUT_DEFAULT;
    c->io_buffer_size       = CONFIG_IO_BUFFER_SIZE_DEFAULT;
    c->max_connections      = max_connections_hard;
    c->max_connections_hard = max_connections_hard;
}

uint32_t config_conn_timeout(const struct Config *c)    { return c->conn_timeout; }
uint32_t config_io_buffer_size(const struct Config *c)  { return c->io_buffer_size; }
uint32_t config_max_connections(const struct Config *c) { return c->max_connections; }

bool config_set_conn_timeout(struct Config *c, uint32_t v)
{
    if (v < CONFIG_CONN_TIMEOUT_MIN || v > CONFIG_CONN_TIMEOUT_MAX) {
        return false;
    }
    c->conn_timeout = v;
    return true;
}

bool config_set_io_buffer_size(struct Config *c, uint32_t v)
{
    if (v < CONFIG_IO_BUFFER_SIZE_MIN || v > CONFIG_IO_BUFFER_SIZE_MAX) {
        return false;
    }
    c->io_buffer_size = v;
    return true;
}

bool config_set_max_connections(struct Config *c, uint32_t v)
{
    if (v < 1 || v > c->max_connections_hard) {
        return false;
    }
    c->max_connections = v;
    return true;
}
