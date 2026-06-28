#include "request.h"

#include <netinet/in.h>

#define SOCKS5_VERSION 0x05

void request_parser_init(struct socks5_request *p)
{
    p->state     = REQ_VER;
    p->cmd       = 0;
    p->atyp      = 0;
    p->addr_len  = 0;
    p->addr_read = 0;
    p->dst_port  = 0;
    p->port_read = 0;
}

req_state request_parser_feed(struct socks5_request *p, buffer *b)
{
    while (buffer_can_read(b) && p->state != REQ_DONE && p->state != REQ_ERROR) {
        uint8_t c = buffer_read(b);
        switch (p->state) {
            case REQ_VER:
                p->state = (c == SOCKS5_VERSION) ? REQ_CMD : REQ_ERROR;
                break;
            case REQ_CMD:
                p->cmd   = c; /* registramos CMD; la política la decide quien consume */
                p->state = REQ_RSV;
                break;
            case REQ_RSV:
                p->state = (c == 0x00) ? REQ_ATYP : REQ_ERROR;
                break;
            case REQ_ATYP:
                p->atyp = c;
                if (c == SOCKS5_ATYP_IPV4) {
                    p->addr_len = 4;
                    p->state    = REQ_DADDR;
                } else if (c == SOCKS5_ATYP_IPV6) {
                    p->addr_len = 16;
                    p->state    = REQ_DADDR;
                } else if (c == SOCKS5_ATYP_DOMAIN) {
                    p->state = REQ_DLEN;
                } else {
                    p->state = REQ_ERROR;
                }
                break;
            case REQ_DLEN:
                p->addr_len = c; /* longitud del dominio */
                p->state    = (c == 0) ? REQ_ERROR : REQ_DADDR;
                break;
            case REQ_DADDR:
                p->dst_addr[p->addr_read++] = c;
                if (p->addr_read == p->addr_len) {
                    p->state = REQ_DPORT;
                }
                break;
            case REQ_DPORT:
                p->dst_port = (uint16_t)((p->dst_port << 8) | c);
                if (++p->port_read == 2) {
                    p->state = REQ_DONE;
                }
                break;
            default:
                break;
        }
    }
    return p->state;
}

bool request_done(const struct socks5_request *p)
{
    return p->state == REQ_DONE;
}

void fill_request_reply(buffer *b, uint8_t rep, uint8_t atyp)
{
    if (atyp != SOCKS5_ATYP_IPV6) {
        atyp = SOCKS5_ATYP_IPV4;
    }

    buffer_write(b, SOCKS5_VERSION);
    buffer_write(b, rep);
    buffer_write(b, 0x00);  /* RSV */
    buffer_write(b, atyp);

    const int addr_len = (atyp == SOCKS5_ATYP_IPV6) ? 16 : 4;
    for (int i = 0; i < addr_len; i++) {
        buffer_write(b, 0x00);
    }
    buffer_write(b, 0x00);  /* BND.PORT = 0 */
    buffer_write(b, 0x00);
}

bool fill_request_reply_addr(buffer *b, uint8_t rep, const struct sockaddr *addr)
{
    const uint8_t *addr_bytes = NULL;
    size_t         addr_len   = 0;
    uint8_t        atyp       = SOCKS5_ATYP_IPV4;
    uint16_t       port       = 0;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sa4 = (const struct sockaddr_in *)addr;
        atyp       = SOCKS5_ATYP_IPV4;
        addr_bytes = (const uint8_t *)&sa4->sin_addr;
        addr_len   = 4;
        port       = ntohs(sa4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)addr;
        atyp       = SOCKS5_ATYP_IPV6;
        addr_bytes = (const uint8_t *)&sa6->sin6_addr;
        addr_len   = 16;
        port       = ntohs(sa6->sin6_port);
    } else {
        return false;
    }

    buffer_write(b, SOCKS5_VERSION);
    buffer_write(b, rep);
    buffer_write(b, 0x00);
    buffer_write(b, atyp);
    for (size_t i = 0; i < addr_len; i++) {
        buffer_write(b, addr_bytes[i]);
    }
    buffer_write(b, (uint8_t)(port >> 8));
    buffer_write(b, (uint8_t)(port & 0xFF));
    return true;
}
