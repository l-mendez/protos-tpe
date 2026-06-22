#ifndef REQUEST_H_socks5_request_parser
#define REQUEST_H_socks5_request_parser

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

/**
 * request.c -- parser del request SOCKS5 (RFC 1928 §4).
 *
 *   +-----+-----+-------+------+----------+----------+
 *   | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *   +-----+-----+-------+------+----------+----------+
 *   |  1  |  1  | 0x00  |  1   | variable |    2     |
 *   +-----+-----+-------+------+----------+----------+
 *
 * Parser reentrante byte-a-byte: el progreso (estado, bytes leídos de la
 * dirección y del puerto) vive en la estructura, por lo que tolera lecturas
 * parciales en cualquier punto del mensaje.
 *
 * El parser es agnóstico a la política: registra CMD y ATYP pero no rechaza
 * comandos; quién consume decide qué soporta (sólo CONNECT, por ahora).
 */

typedef enum {
    REQ_VER = 0, /* esperando VER (0x05) */
    REQ_CMD,     /* esperando CMD */
    REQ_RSV,     /* esperando RSV (0x00) */
    REQ_ATYP,    /* esperando ATYP */
    REQ_DLEN,    /* sólo dominio: byte de longitud que fija addr_len */
    REQ_DADDR,   /* leyendo DST.ADDR (addr_len bytes) */
    REQ_DPORT,   /* leyendo DST.PORT (2 bytes) */
    REQ_DONE,    /* request completo */
    REQ_ERROR    /* error de protocolo */
} req_state;

/* ATYP (RFC 1928 §4). */
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04

/* CMD (RFC 1928 §4). */
#define SOCKS5_CMD_CONNECT 0x01

/* REP: códigos de respuesta del request (RFC 1928 §6). */
#define SOCKS5_REP_SUCCESS           0x00
#define SOCKS5_REP_GENERAL_FAILURE   0x01
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE    0x04
#define SOCKS5_REP_CONNECTION_REFUSED  0x05
#define SOCKS5_REP_TTL_EXPIRED         0x06
#define SOCKS5_REP_CMD_NOT_SUPPORTED   0x07
#define SOCKS5_REP_ATYP_NOT_SUPPORTED  0x08

struct socks5_request {
    req_state state; /* el progreso vive acá, explícito */

    uint8_t  cmd;
    uint8_t  atyp;
    uint8_t  dst_addr[256]; /* dominio (<=255) o bytes de IPv4/IPv6 */
    uint8_t  addr_len;      /* cuántos bytes de addr esperás (lo fija ATYP/DLEN) */
    uint8_t  addr_read;     /* cuántos llevás leídos */
    uint16_t dst_port;
    uint8_t  port_read;     /* 0, 1 o 2 bytes del puerto */
};

/** deja el parser en su estado inicial */
void
request_parser_init(struct socks5_request *p);

/** consume los bytes disponibles en `b`, avanzando el parser. retorna el estado. */
req_state
request_parser_feed(struct socks5_request *p, buffer *b);

/** true si el request se parseó por completo */
bool
request_done(const struct socks5_request *p);

/**
 * Escribe una respuesta de request (RFC 1928 §6) en `b` con el código `rep` y un
 * BND.ADDR/PORT nulo (0.0.0.0:0, ATYP IPv4). Pensado para las respuestas de
 * error: 10 bytes VER REP RSV ATYP BND.ADDR BND.PORT.
 */
void
fill_request_reply(buffer *b, uint8_t rep);

#endif
