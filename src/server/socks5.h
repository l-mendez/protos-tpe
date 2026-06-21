#ifndef SOCKS5_H_socks5_connection_handler
#define SOCKS5_H_socks5_connection_handler

#include <stddef.h>

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

/** Cantidad de conexiones SOCKS5 actualmente registradas (para drenar al apagar). */
size_t
socks5_active_connections(void);

#endif
