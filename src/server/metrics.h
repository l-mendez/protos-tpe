#ifndef METRICS_H_socks5_runtime_metrics
#define METRICS_H_socks5_runtime_metrics

#include <stddef.h>
#include <stdint.h>

/**
 * metrics.c -- métricas volátiles de operación del servidor.
 *
 * El estado vive en una `struct metrics` cuyo almacenamiento provee el llamador
 * (mismo estilo que buffer/auth): main() la crea y la inyecta en los módulos que
 * la actualizan. Hay una única instancia por proceso.
 *
 * Todas las funciones de registro se invocan desde el hilo del selector (el
 * único que toca las conexiones), por lo que no hay concurrencia y no se
 * necesitan atómicos ni locks. El pool de resolución DNS corre en otros hilos
 * pero jamás llama acá.
 *
 * El protocolo de monitoreo lee una foto consistente vía metrics_get().
 */
struct Metrics {
    uint64_t historical_connections;     /* conexiones aceptadas desde el arranque */
    size_t   active_connections;     /* conexiones activas ahora */
    size_t   max_active_connections; /* pico histórico de concurrentes */
    uint64_t bytes_client_to_origin;     /* bytes relayados cliente -> origen */
    uint64_t bytes_origin_to_client;     /* bytes relayados origen -> cliente */
};


/** Deja todos los contadores en cero. El llamador provee el almacenamiento. */
void
metrics_init(struct Metrics *m);

/** Registra una conexión aceptada: incrementa histórico y concurrentes, y
 *  actualiza el pico de concurrentes. */
void
metrics_connection_opened(struct Metrics *m);

/** Registra el cierre de una conexión previamente contada. */
void
metrics_connection_closed(struct Metrics *m);

/** Suma `n` bytes relayados en sentido cliente -> origen. */
void
metrics_bytes_client_to_origin(struct Metrics *m, size_t n);

/** Suma `n` bytes relayados en sentido origen -> cliente. */
void
metrics_bytes_origin_to_client(struct Metrics *m, size_t n);


#endif
