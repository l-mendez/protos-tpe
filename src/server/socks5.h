#ifndef SOCKS5_H_socks5_connection_handler
#define SOCKS5_H_socks5_connection_handler

#include <stddef.h>

#include "args.h"
#include "selector.h"

/**
 * socks5.c -- handler de conexión SOCKS5 (RFC 1928) modelado como máquina de
 * estados (stm).
 *
 * En esta ronda se parsean dos fases: la negociación de métodos y el request
 * (CMD/ATYP/dirección/puerto), avanzando entre estados y tolerando lecturas
 * parciales. Resolución de nombres, conexión al origen y relay quedan para
 * rondas siguientes; al completar el request la conexión registra el destino y
 * termina.
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

/** Cantidad de conexiones SOCKS5 actualmente registradas (para drenar al apagar). */
size_t
socks5_active_connections(void);

#endif
