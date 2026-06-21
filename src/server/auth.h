#ifndef AUTH_H_socks5_userpass_auth
#define AUTH_H_socks5_userpass_auth

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

/**
 * auth.c -- parser de la autenticación usuario/contraseña SOCKS5 (RFC 1929).
 *
 *   +-----+------+----------+------+----------+
 *   | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *   +-----+------+----------+------+----------+
 *   |  1  |  1   | 1 .. 255 |  1   | 1 .. 255 |
 *   +-----+------+----------+------+----------+
 *
 * Ojo: VER de este subprotocolo es 0x01, NO el 0x05 de SOCKS.
 *
 * Parser reentrante byte-a-byte: el progreso (estado, bytes leídos de usuario y
 * contraseña) vive en la estructura, por lo que tolera lecturas parciales en
 * cualquier punto del mensaje. ULEN/PLEN de 0 son válidos (campo vacío).
 */

typedef enum {
    AUTH_VER = 0, /* esperando VER (0x01) */
    AUTH_ULEN,    /* esperando ULEN */
    AUTH_UNAME,   /* leyendo username (ULEN bytes) */
    AUTH_PLEN,    /* esperando PLEN */
    AUTH_PASSWD,  /* leyendo password (PLEN bytes) */
    AUTH_DONE,    /* mensaje completo */
    AUTH_ERROR    /* error de protocolo */
} auth_state;

/* Subprotocolo de auth (RFC 1929). */
#define SOCKS5_AUTH_VERSION 0x01
#define SOCKS5_AUTH_OK      0x00
#define SOCKS5_AUTH_FAIL    0x01

struct socks5_auth {
    auth_state state; /* el progreso vive acá, explícito */

    uint8_t ulen;
    uint8_t uname[256];  /* 255 + '\0' para poder strcmp */
    uint8_t uname_read;  /* progreso dentro del username */
    uint8_t plen;
    uint8_t passwd[256]; /* 255 + '\0' */
    uint8_t passwd_read; /* progreso dentro del password */
};

/** deja el parser en su estado inicial */
void
auth_parser_init(struct socks5_auth *p);

/** consume los bytes disponibles en `b`, avanzando el parser. retorna el estado. */
auth_state
auth_parser_feed(struct socks5_auth *p, buffer *b);

/** true si las credenciales se parsearon por completo */
bool
auth_done(const struct socks5_auth *p);

/** escribe la respuesta de 2 bytes (VER + STATUS) de RFC 1929 en `b`. */
void
fill_auth_reply(buffer *b, uint8_t status);

#endif
