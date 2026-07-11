#include "mgmt_parser.h"

void
mgmt_parser_init(struct mgmt_parser *p)
{
    p->len      = 0;
    p->overflow = false;
    p->line[0]  = '\0';
}

void
mgmt_parser_reset(struct mgmt_parser *p)
{
    p->len      = 0;
    p->overflow = false;
    p->line[0]  = '\0';
}

mgmt_line_state
mgmt_parser_feed(struct mgmt_parser *p, buffer *b)
{
    while (buffer_can_read(b)) {
        uint8_t c = buffer_read(b);

        if (c == '\n') {
            if (p->overflow) {
                return MGMT_LINE_TOO_LONG;
            }
            /* tolerar un CR previo al LF */
            if (p->len > 0 && p->line[p->len - 1] == '\r') {
                p->len--;
            }
            p->line[p->len] = '\0';
            return MGMT_LINE_READY;
        }

        if (p->overflow) {
            continue; /* descartar hasta el LF */
        }
        if (p->len >= MGMT_LINE_MAX - 1) {
            p->overflow = true; /* excede el máximo: descartar el resto */
            continue;
        }
        p->line[p->len++] = (char)c;
    }
    return MGMT_LINE_INCOMPLETE;
}

int
mgmt_tokenize(char *line, char **argv, int max_args)
{
    int   argc = 0;
    char *s    = line;

    while (*s != '\0' && argc < max_args) {
        while (*s == ' ') {
            s++; /* saltear espacios (colapsa múltiples) */
        }
        if (*s == '\0') {
            break;
        }
        argv[argc++] = s;
        while (*s != '\0' && *s != ' ') {
            s++;
        }
        if (*s == ' ') {
            *s = '\0';
            s++;
        }
    }
    return argc;
}
