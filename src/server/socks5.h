#ifndef SOCKS5_H_socks5_connection_handler
#define SOCKS5_H_socks5_connection_handler

#include <stdbool.h>
#include <stddef.h>

#include "args.h"
#include "selector.h"

/**
 * socks5.c -- handler de conexión SOCKS5 (RFC 1928) modelado como máquina de
 * estados (stm).
 *
 * Implementa la negociación de métodos, autenticación usuario/contraseña
 * (RFC 1929), parseo del request, resolución DNS (en hilo aparte para FQDNs),
 * conexión no bloqueante al origen con reintento de direcciones y relay
 * full-duplex del tráfico entre cliente y origen.
 */

/**
 * Handler de lectura para el socket pasivo: acepta la conexión entrante, la pone
 * en modo no bloqueante y la registra en el selector con su propia stm SOCKS5.
 */
void
socks5_passive_accept(struct selector_key *key);

/**
 * Registra los usuarios configurados (-u user:pass) contra los que se validan
 * las credenciales durante la autenticación user/pass (RFC 1929). El arreglo
 * apuntado debe sobrevivir a todas las conexiones (vive en main()).
 */
void
socks5_set_users(const struct socks5args *args);

/** Inicializa el pool acotado de resolución DNS. Es idempotente. */
bool
socks5_resolver_pool_start(void);

/** Detiene el pool de resolución DNS y cancela trabajos pendientes. */
void
socks5_resolver_pool_stop(void);

/** Cantidad de conexiones SOCKS5 actualmente registradas (para drenar al apagar). */
size_t
socks5_active_connections(void);

/**
 * Recorre las conexiones activas y cierra las que llevan más de
 * SOCKS5_INACTIVITY_TIMEOUT segundos sin actividad.  Debe llamarse desde el
 * loop principal después de cada selector_select.
 */
void
socks5_reap_idle(fd_selector s);

#endif
