#ifndef MGMT_PARSER_H_smcp_line_parser
#define MGMT_PARSER_H_smcp_line_parser

#include <stdbool.h>
#include <stddef.h>

#include "buffer.h"

/**
 * mgmt_parser.c -- parser de líneas del protocolo de monitoreo (SMCP).
 *
 * SMCP es de texto orientado a líneas terminadas en LF (un CR previo se tolera y
 * descarta). Este parser es reentrante: acumula bytes de un `buffer` hasta
 * completar una línea, tolerando lecturas parciales (una línea puede llegar en
 * varios segmentos) y pipelining (varias líneas en un mismo segmento).
 *
 * Una línea no puede exceder MGMT_LINE_MAX bytes (incluido el terminador); si se
 * excede, se reporta MGMT_LINE_TOO_LONG y se descartan los bytes hasta el próximo
 * LF (protección de memoria).
 *
 * Uso típico en el handler de lectura:
 *   for (;;) {
 *       st = mgmt_parser_feed(&p, b);
 *       if (st == MGMT_LINE_INCOMPLETE) break;
 *       if (st == MGMT_LINE_READY)    { dispatch(p.line); }
 *       // else MGMT_LINE_TOO_LONG   -> responder error
 *       mgmt_parser_reset(&p);       // preparar la próxima línea
 *   }
 */

#define MGMT_LINE_MAX 4096 /* tamaño máx. de línea, incluido el terminador */

typedef enum {
    MGMT_LINE_INCOMPLETE = 0, /* falta más entrada para completar la línea */
    MGMT_LINE_READY,          /* hay una línea completa en `line` */
    MGMT_LINE_TOO_LONG,       /* la línea excedió el máximo; se descartó */
    MGMT_LINE_INVALID,        /* byte fuera de ASCII imprimible; se descartó */
} mgmt_line_state;

struct mgmt_parser {
    char   line[MGMT_LINE_MAX]; /* línea acumulada, sin CR/LF, NUL-terminada al completar */
    size_t len;                 /* bytes de contenido acumulados */
    bool   overflow;            /* se excedió el máximo: descartar hasta el LF */
    bool   invalid;             /* byte no imprimible: descartar hasta el LF */
};

/** Deja el parser listo para acumular una línea nueva. */
void
mgmt_parser_init(struct mgmt_parser *p);

/**
 * Consume bytes de `b` hasta completar una línea, detectar overflow, o agotar la
 * entrada. Ver mgmt_line_state. Tras READY/TOO_LONG hay que llamar a
 * mgmt_parser_reset antes de volver a llamar para la próxima línea.
 */
mgmt_line_state
mgmt_parser_feed(struct mgmt_parser *p, buffer *b);

/** Reinicia el estado para parsear la próxima línea. */
void
mgmt_parser_reset(struct mgmt_parser *p);

/**
 * Parte `line` in situ en tokens separados por espacios (colapsa espacios
 * múltiples). Llena `argv` con hasta `max_args` punteros dentro de `line` y
 * devuelve la cantidad de tokens.
 */
int
mgmt_tokenize(char *line, char **argv, int max_args);

#endif
