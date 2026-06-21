#include "auth.h"

void auth_parser_init(struct socks5_auth *p)
{
    p->state       = AUTH_VER;
    p->ulen        = 0;
    p->uname_read  = 0;
    p->uname[0]    = '\0';
    p->plen        = 0;
    p->passwd_read = 0;
    p->passwd[0]   = '\0';
}

auth_state auth_parser_feed(struct socks5_auth *p, buffer *b)
{
    while (buffer_can_read(b) && p->state != AUTH_DONE && p->state != AUTH_ERROR) {
        uint8_t c = buffer_read(b);
        switch (p->state) {
            case AUTH_VER:
                p->state = (c == SOCKS5_AUTH_VERSION) ? AUTH_ULEN : AUTH_ERROR;
                break;
            case AUTH_ULEN:
                p->ulen       = c;
                p->uname_read = 0;
                if (c == 0) {
                    /* ULEN==0: username vacío, saltar directo a PLEN. */
                    p->uname[0] = '\0';
                    p->state    = AUTH_PLEN;
                } else {
                    p->state = AUTH_UNAME;
                }
                break;
            case AUTH_UNAME:
                p->uname[p->uname_read++] = c;
                if (p->uname_read == p->ulen) {
                    p->uname[p->ulen] = '\0';
                    p->state          = AUTH_PLEN;
                }
                break;
            case AUTH_PLEN:
                p->plen        = c;
                p->passwd_read = 0;
                if (c == 0) {
                    /* PLEN==0: password vacío, terminar. */
                    p->passwd[0] = '\0';
                    p->state     = AUTH_DONE;
                } else {
                    p->state = AUTH_PASSWD;
                }
                break;
            case AUTH_PASSWD:
                p->passwd[p->passwd_read++] = c;
                if (p->passwd_read == p->plen) {
                    p->passwd[p->plen] = '\0';
                    p->state           = AUTH_DONE;
                }
                break;
            default:
                break;
        }
    }
    return p->state;
}

bool auth_done(const struct socks5_auth *p)
{
    return p->state == AUTH_DONE;
}

void fill_auth_reply(buffer *b, uint8_t status)
{
    buffer_write(b, SOCKS5_AUTH_VERSION);
    buffer_write(b, status);
}
