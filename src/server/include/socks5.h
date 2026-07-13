#ifndef SOCKS5_H_socks5_connection_handler
#define SOCKS5_H_socks5_connection_handler

#include <stdbool.h>
#include <stddef.h>

#include "access_log.h"
#include "args.h"
#include "config.h"
#include "metrics.h"
#include "selector.h"
#include "users.h"

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
 * Inyecta el almacén de usuarios del proxy contra el que se validan las
 * credenciales durante la autenticación user/pass (RFC 1929). El almacén vive en
 * main() y puede ser modificado en caliente por el protocolo de monitoreo; debe
 * sobrevivir a todas las conexiones.
 */
void
socks5_set_users(struct Users *users);

/**
 * Inyecta la instancia de métricas del proceso. Debe llamarse antes de aceptar
 * conexiones. El almacenamiento vive en main() durante toda la ejecución.
 */
void
socks5_set_metrics(struct Metrics *m);

/**
 * Inyecta el registro de accesos. Si no se llama (o se pasa NULL), los intentos
 * de CONNECT no se registran. El almacenamiento vive en main().
 */
void
socks5_set_access_log(struct AccessLog *l);

/**
 * Inyecta la configuración runtime (timeouts, tope de conexiones, tamaño de
 * buffer). Si no se llama, se usan los defaults de compilación. Vive en main().
 */
void
socks5_set_config(struct Config *cfg);

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
