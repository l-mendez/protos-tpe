#ifndef ECHO_H_RWNobyBzZXJ2ZXIgc2NhZmZvbGQ
#define ECHO_H_RWNobyBzZXJ2ZXIgc2NhZmZvbGQ

#include <stddef.h>

#include "selector.h"

/**
 * Handler de lectura para un socket pasivo: acepta una conexión entrante, la
 * pone en modo no bloqueante y la registra en el selector como una conexión
 * "echo" (todo lo que llega se devuelve tal cual).
 *
 * Pensado como andamiaje previo a SOCKS5: ejercita selector + buffer de punta
 * a punta antes de sumar lógica de protocolo.
 */
void
echo_passive_accept(struct selector_key *key);

/** Cantidad de conexiones echo actualmente registradas en el selector. */
size_t
echo_active_connections(void);

#endif
