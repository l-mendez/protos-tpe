#ifndef SOCKS5_INTERNAL_H_connection_state_and_resolver
#define SOCKS5_INTERNAL_H_connection_state_and_resolver

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "auth.h"
#include "buffer.h"
#include "negotiation.h"
#include "request.h"
#include "selector.h"
#include "stm.h"

struct resolver_job;

/** Estado por conexión: stm + parsers + buffers + estado de conexión/relay. */
struct socks5_conn {
    struct state_machine stm;

    struct negotiation_parser neg;
    struct socks5_auth        auth;
    struct socks5_request     request;

    uint8_t method;      /* método elegido en la negociación */
    uint8_t auth_status; /* resultado de auth, a enviar en AUTH_WRITE */

    fd_selector selector;
    int         client_fd;
    int         origin_fd;
    int         references;

    time_t       last_activity;
    struct socks5_conn *prev;
    struct socks5_conn *next;

    struct addrinfo        *resolution;
    struct addrinfo        *next_addr;
    struct addrinfo         literal_ai;
    struct sockaddr_storage literal_sa;
    int                     last_errno;
    int                     resolver_error;
    struct resolver_job    *resolver_job;
    bool                    resolver_done;
    bool                    connected;

    bool client_closed;
    bool origin_closed;
    bool client_wr_shut;
    bool origin_wr_shut;
    fd_interest client_interest;
    fd_interest origin_interest;
    bool active_counted;
    bool arrival_error;

    struct buffer read_buffer;
    struct buffer write_buffer;
    uint8_t      *raw_read;
    uint8_t      *raw_write;
};

void
socks5_conn_free_if_unreferenced(struct socks5_conn *c);

bool
socks5_resolver_queue_job(struct socks5_conn *c, const char *host,
                          const char *port);

void
socks5_resolver_cancel_conn(struct socks5_conn *c);

bool
socks5_resolver_take_completed(struct socks5_conn *c);

bool
socks5_resolver_is_completed(struct socks5_conn *c);

#endif
