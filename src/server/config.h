#ifndef CONFIG_H_socks5_runtime_config
#define CONFIG_H_socks5_runtime_config

#include <stdbool.h>
#include <stdint.h>

/**
 * config.c -- parámetros de configuración modificables en tiempo de ejecución
 * por el protocolo de monitoreo (comando SET / GET-CONFIG).
 *
 * Estilo de instancia (como Metrics/Users): el llamador provee el almacenamiento.
 * Los setters validan rango y devuelven false si el valor es inválido (dejando
 * el valor anterior intacto).
 */

#define CONFIG_CONN_TIMEOUT_DEFAULT   60u   /* segundos */
#define CONFIG_CONN_TIMEOUT_MIN        1u
#define CONFIG_CONN_TIMEOUT_MAX     3600u

#define CONFIG_IO_BUFFER_SIZE_DEFAULT 4096u /* bytes */
#define CONFIG_IO_BUFFER_SIZE_MIN      512u
#define CONFIG_IO_BUFFER_SIZE_MAX    65536u

struct Config {
    uint32_t conn_timeout;         /* inactividad (s) antes de cerrar (handshake) */
    uint32_t io_buffer_size;       /* buffer de relay por conexión nueva (bytes) */
    uint32_t max_connections;      /* tope blando de conexiones concurrentes */
    uint32_t max_connections_hard; /* techo: capacidad del selector, no superable */
};

/**
 * Inicializa con los defaults. `max_connections` arranca en el techo
 * `max_connections_hard` (la capacidad con la que se creó el multiplexor).
 */
void
config_init(struct Config *c, uint32_t max_connections_hard);

uint32_t config_conn_timeout(const struct Config *c);
uint32_t config_io_buffer_size(const struct Config *c);
uint32_t config_max_connections(const struct Config *c);

/** Setters validados. Devuelven false (sin cambiar nada) si el valor es inválido. */
bool config_set_conn_timeout(struct Config *c, uint32_t v);
bool config_set_io_buffer_size(struct Config *c, uint32_t v);
bool config_set_max_connections(struct Config *c, uint32_t v);

#endif
