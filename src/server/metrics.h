#ifndef METRICS_H_socks5_runtime_metrics
#define METRICS_H_socks5_runtime_metrics

#include <stddef.h>
#include <stdint.h>

/**
 * metrics.c -- métricas volátiles de operación del servidor.
 *
 * Todas las funciones de registro se invocan desde el hilo del selector (el
 * único que toca las conexiones), por lo que los contadores son simples: no hay
 * concurrencia y no se necesitan atómicos ni locks. El pool de resolución DNS
 * corre en otros hilos pero jamás llama acá.
 *
 * El protocolo de monitoreo lee una foto consistente vía metrics_get().
 */

/** Foto por valor de todas las métricas en un instante dado. */
struct metrics_snapshot {
    uint64_t historical_connections;     /* conexiones aceptadas desde el arranque */
    size_t   concurrent_connections;     /* conexiones activas ahora */
    size_t   max_concurrent_connections; /* pico histórico de concurrentes */
    uint64_t bytes_client_to_origin;     /* bytes relayados cliente -> origen */
    uint64_t bytes_origin_to_client;     /* bytes relayados origen -> cliente */
    uint64_t total_bytes;                /* suma de ambas direcciones */
};

/** Registra una conexión aceptada: incrementa histórico y concurrentes, y
 *  actualiza el pico de concurrentes. */
void
metrics_connection_opened(void);

/** Registra el cierre de una conexión previamente contada. */
void
metrics_connection_closed(void);

/** Suma `n` bytes relayados en sentido cliente -> origen. */
void
metrics_bytes_client_to_origin(size_t n);

/** Suma `n` bytes relayados en sentido origen -> cliente. */
void
metrics_bytes_origin_to_client(size_t n);

/** Devuelve una copia de las métricas actuales (con total_bytes calculado). */
struct metrics_snapshot
metrics_get(void);

#endif
