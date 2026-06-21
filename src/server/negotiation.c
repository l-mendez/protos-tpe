#include "negotiation.h"

#define SOCKS5_VERSION 0x05

void negotiation_parser_init(struct negotiation_parser *p)
{
    p->state           = NEG_VERSION;
    p->pending_methods = 0;
    p->has_userpass    = false;
    p->has_noauth      = false;
}

neg_state negotiation_parser_feed(struct negotiation_parser *p, buffer *b)
{
    while (buffer_can_read(b) && p->state != NEG_DONE && p->state != NEG_INVALID) {
        uint8_t c = buffer_read(b);
        switch (p->state) {
            case NEG_VERSION:
                p->state = (c == SOCKS5_VERSION) ? NEG_NMETHODS : NEG_INVALID;
                break;
            case NEG_NMETHODS:
                p->pending_methods = c;
                p->state           = (c == 0) ? NEG_DONE : NEG_METHODS;
                break;
            case NEG_METHODS:
                if (c == SOCKS5_METHOD_USERPASS) {
                    p->has_userpass = true;
                } else if (c == SOCKS5_METHOD_NOAUTH) {
                    p->has_noauth = true;
                }
                if (--p->pending_methods == 0) {
                    p->state = NEG_DONE;
                }
                break;
            default:
                break;
        }
    }
    return p->state;
}

bool negotiation_done(const struct negotiation_parser *p)
{
    return p->state == NEG_DONE;
}

uint8_t fill_negotiation_reply(const struct negotiation_parser *p, buffer *b)
{
    uint8_t method = SOCKS5_METHOD_NONE;
    if (p->has_userpass) {
        method = SOCKS5_METHOD_USERPASS;
    } else if (p->has_noauth) {
        method = SOCKS5_METHOD_NOAUTH;
    }

    buffer_write(b, SOCKS5_VERSION);
    buffer_write(b, method);
    return method;
}
