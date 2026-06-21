#ifndef NEGOTIATION_H_socks5_method_negotiation
#define NEGOTIATION_H_socks5_method_negotiation

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

/**
 * negotiation.c -- parser de la negociación de métodos SOCKS5 (RFC 1928 §3).
 *
 *   +-----+----------+----------+
 *   | VER | NMETHODS | METHODS  |
 *   +-----+----------+----------+
 *   |  1  |    1     | 1 .. 255 |
 *   +-----+----------+----------+
 *
 * Es un parser reentrante byte-a-byte: el progreso vive en la estructura, así
 * que tolera lecturas parciales (el mensaje puede llegar en cualquier cantidad
 * de fragmentos).
 */

typedef enum {
    NEG_VERSION = 0, /* esperando VER (debe ser 0x05) */
    NEG_NMETHODS,    /* esperando NMETHODS */
    NEG_METHODS,     /* leyendo los METHODS */
    NEG_DONE,        /* mensaje completo */
    NEG_INVALID      /* error de protocolo */
} neg_state;

/* Métodos de autenticación relevantes (RFC 1928 §3). GSSAPI no es requerido por
 * la consigna, así que cualquier otro método se ignora. */
#define SOCKS5_METHOD_NOAUTH   0x00
#define SOCKS5_METHOD_USERPASS 0x02
#define SOCKS5_METHOD_NONE     0xFF

struct negotiation_parser {
    neg_state state;
    uint8_t   pending_methods; /* cuántos METHODS faltan leer */
    bool      has_userpass;    /* se ofreció 0x02 */
    bool      has_noauth;      /* se ofreció 0x00 */
};

/** deja el parser en su estado inicial */
void
negotiation_parser_init(struct negotiation_parser *p);

/** consume los bytes disponibles en `b`, avanzando el parser. retorna el estado. */
neg_state
negotiation_parser_feed(struct negotiation_parser *p, buffer *b);

/** true si el parser terminó (con éxito) */
bool
negotiation_done(const struct negotiation_parser *p);

/**
 * Escribe la respuesta de 2 bytes (VER + METHOD) en `b` eligiendo el método:
 * prefiere user/pass si se ofreció, si no no-auth, si no 0xFF. Retorna el
 * método elegido.
 */
uint8_t
fill_negotiation_reply(const struct negotiation_parser *p, buffer *b);

#endif
