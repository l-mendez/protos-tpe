#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "args.h"
#include "auth.h"
#include "buffer.h"
#include "negotiation.h"
#include "request.h"
#include "socks5.h"
#include "stm.h"

#define SOCKS5_BUFFER_SIZE 4096

/* Linux evita el SIGPIPE en send() con esta flag; macOS no la define y lo
 * resuelve ignorando SIGPIPE en el arranque, así que aquí degrada a 0. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* En un socket no bloqueante, recv/send pueden devolver -1 con uno de estos
 * errno: no es un fallo de la conexión, hay que reintentar más tarde. */
static inline int would_block(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

/* Estados de la conexión SOCKS5. Sólo se definen las fases de esta ronda; auth,
 * resolución, conexión al origen y relay se intercalan en rondas siguientes. */
enum socks5_state {
    NEG_READ = 0, /* leyendo/parseando la negociación de métodos */
    NEG_WRITE,    /* escribiendo la respuesta de método (2 bytes) */
    AUTH_READ,    /* leyendo/parseando las credenciales user/pass (RFC 1929) */
    AUTH_WRITE,   /* escribiendo la respuesta de auth (2 bytes) */
    REQ_READ,     /* leyendo/parseando el request */
    DONE,         /* terminal: request parseado (placeholder de esta ronda) */
    ERROR,        /* terminal: error de protocolo o de I/O */
};

/** Estado por conexión: stm + parsers + buffers cliente. */
struct socks5_conn {
    struct state_machine stm;

    struct negotiation_parser neg;
    struct socks5_auth        auth;
    struct socks5_request     request;

    uint8_t method;      /* método elegido en la negociación */
    uint8_t auth_status; /* resultado de auth, a enviar en AUTH_WRITE */

    struct buffer read_buffer;
    struct buffer write_buffer;
    uint8_t       raw_read[SOCKS5_BUFFER_SIZE];
    uint8_t       raw_write[SOCKS5_BUFFER_SIZE];
};

static size_t active_connections = 0;

/* Usuarios configurados por línea de comandos (-u user:pass). Apuntan al arreglo
 * de `struct socks5args`, que vive durante toda la ejecución en main(). */
static const struct users *configured_users = NULL;

void socks5_set_users(const struct socks5args *args)
{
    configured_users = args->users;
}

/* true si hay al menos un usuario configurado: en ese caso la autenticación
 * user/pass es obligatoria durante la negociación. */
static bool auth_required(void)
{
    return configured_users != NULL && configured_users[0].name != NULL;
}

/* Valida user/pass contra los usuarios configurados. El arreglo está terminado
 * por un name == NULL (o llega a MAX_USERS): no hay contador explícito. */
static bool credentials_match(const char *user, const char *pass)
{
    if (configured_users == NULL) {
        return false;
    }
    for (int i = 0; i < MAX_USERS && configured_users[i].name != NULL; i++) {
        if (strcmp(configured_users[i].name, user) == 0) {
            return strcmp(configured_users[i].pass, pass) == 0;
        }
    }
    return false;
}

size_t socks5_active_connections(void)
{
    return active_connections;
}

/* ------------------------------------------------------------------ helpers */

/* Lee del socket al read_buffer. Devuelve el estado a transicionar ante un
 * fin/error de conexión, o -1 si la lectura fue exitosa (seguir parseando). */
static int fill_read_buffer(struct selector_key *key, struct buffer *b)
{
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    ssize_t  n   = recv(key->fd, ptr, space, 0);
    if (n > 0) {
        buffer_write_adv(b, n);
        return -1;
    }
    if (n < 0 && would_block(errno)) {
        return -1; /* sin datos por ahora: el parser simplemente no avanza */
    }
    return ERROR; /* n == 0 (cierre del par) o error real */
}

/* --------------------------------------------------------- negotiation phase */

static void negotiation_read_init(const unsigned state, struct selector_key *key)
{
    (void)state;
    struct socks5_conn *c = key->data;
    negotiation_parser_init(&c->neg);
}

static unsigned negotiation_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    int closed = fill_read_buffer(key, &c->read_buffer);
    if (closed != -1) {
        return (unsigned)closed;
    }

    neg_state st = negotiation_parser_feed(&c->neg, &c->read_buffer);
    if (st == NEG_INVALID) {
        return ERROR;
    }
    if (st != NEG_DONE) {
        return NEG_READ; /* lectura parcial: esperar más datos */
    }

    c->method = fill_negotiation_reply(&c->neg, &c->write_buffer, auth_required());
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return NEG_WRITE;
}

static unsigned negotiation_write(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    size_t   pending;
    uint8_t *ptr = buffer_read_ptr(&c->write_buffer, &pending);
    ssize_t  n   = send(key->fd, ptr, pending, MSG_NOSIGNAL);
    if (n <= 0) {
        return (n < 0 && would_block(errno)) ? NEG_WRITE : ERROR;
    }
    buffer_read_adv(&c->write_buffer, n);

    if (buffer_can_read(&c->write_buffer)) {
        return NEG_WRITE; /* escritura parcial: falta vaciar el buffer */
    }
    /* RFC 1928: si ningún método ofrecido es aceptable se respondió 0xFF y hay
     * que cerrar la conexión (ya se envió el rechazo arriba). */
    if (c->method == SOCKS5_METHOD_NONE) {
        return ERROR;
    }
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    /* Si se negoció user/pass, hay que autenticar antes del request; si se
     * negoció no-auth, se salta directo al request. */
    return (c->method == SOCKS5_METHOD_USERPASS) ? AUTH_READ : REQ_READ;
}

/* --------------------------------------------------------------- auth phase */

static void auth_read_init(const unsigned state, struct selector_key *key)
{
    (void)state;
    struct socks5_conn *c = key->data;
    auth_parser_init(&c->auth);
}

static unsigned auth_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    int closed = fill_read_buffer(key, &c->read_buffer);
    if (closed != -1) {
        return (unsigned)closed;
    }

    auth_state st = auth_parser_feed(&c->auth, &c->read_buffer);
    if (st == AUTH_ERROR) {
        return ERROR;
    }
    if (st != AUTH_DONE) {
        return AUTH_READ; /* lectura parcial: esperar más datos */
    }

    bool ok = credentials_match((const char *)c->auth.uname, (const char *)c->auth.passwd);
    c->auth_status = ok ? SOCKS5_AUTH_OK : SOCKS5_AUTH_FAIL;
    fill_auth_reply(&c->write_buffer, c->auth_status);
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return AUTH_WRITE;
}

static unsigned auth_write(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    size_t   pending;
    uint8_t *ptr = buffer_read_ptr(&c->write_buffer, &pending);
    ssize_t  n   = send(key->fd, ptr, pending, MSG_NOSIGNAL);
    if (n <= 0) {
        return (n < 0 && would_block(errno)) ? AUTH_WRITE : ERROR;
    }
    buffer_read_adv(&c->write_buffer, n);

    if (buffer_can_read(&c->write_buffer)) {
        return AUTH_WRITE; /* escritura parcial: falta vaciar el buffer */
    }
    /* RFC 1929: ante credenciales inválidas hay que cerrar la conexión. */
    if (c->auth_status != SOCKS5_AUTH_OK) {
        return ERROR;
    }
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQ_READ;
}

/* -------------------------------------------------------------- request phase */

static void request_read_init(const unsigned state, struct selector_key *key)
{
    (void)state;
    struct socks5_conn *c = key->data;
    request_parser_init(&c->request);
}

static unsigned request_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    int closed = fill_read_buffer(key, &c->read_buffer);
    if (closed != -1) {
        return (unsigned)closed;
    }

    req_state st = request_parser_feed(&c->request, &c->read_buffer);
    if (st == REQ_ERROR) {
        return ERROR;
    }
    if (st != REQ_DONE) {
        return REQ_READ; /* lectura parcial: esperar más datos */
    }

    /* Esta ronda termina al parsear el request: registramos el destino como
     * evidencia. Resolver/conectar/relay se suman en rondas siguientes. */
    const struct socks5_request *r = &c->request;
    if (r->atyp == SOCKS5_ATYP_DOMAIN) {
        char host[256];
        memcpy(host, r->dst_addr, r->addr_len);
        host[r->addr_len] = '\0';
        printf("socks5: request CONNECT cmd=%u atyp=domain dst=%s:%u\n",
               r->cmd, host, r->dst_port);
    } else {
        char            host[INET6_ADDRSTRLEN] = "?";
        const int       af  = (r->atyp == SOCKS5_ATYP_IPV6) ? AF_INET6 : AF_INET;
        inet_ntop(af, r->dst_addr, host, sizeof(host));
        printf("socks5: request CONNECT cmd=%u atyp=%s dst=%s:%u\n",
               r->cmd, af == AF_INET6 ? "ipv6" : "ipv4", host, r->dst_port);
    }
    return DONE;
}

/* ---------------------------------------------------------------- stm tables */

static const struct state_definition socks5_states[] = {
    {
        .state         = NEG_READ,
        .on_arrival    = negotiation_read_init,
        .on_read_ready = negotiation_read,
    },
    {
        .state          = NEG_WRITE,
        .on_write_ready = negotiation_write,
    },
    {
        .state         = AUTH_READ,
        .on_arrival    = auth_read_init,
        .on_read_ready = auth_read,
    },
    {
        .state          = AUTH_WRITE,
        .on_write_ready = auth_write,
    },
    {
        .state         = REQ_READ,
        .on_arrival    = request_read_init,
        .on_read_ready = request_read,
    },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
    },
};

/* ----------------------------------------------------- selector glue / accept */

static void socks5_done(struct selector_key *key)
{
    selector_unregister_fd(key->s, key->fd);
}

static void socks5_read(struct selector_key *key)
{
    struct socks5_conn *c  = key->data;
    unsigned            st = stm_handler_read(&c->stm, key);
    if (st == ERROR || st == DONE) {
        socks5_done(key);
    }
}

static void socks5_write(struct selector_key *key)
{
    struct socks5_conn *c  = key->data;
    unsigned            st = stm_handler_write(&c->stm, key);
    if (st == ERROR || st == DONE) {
        socks5_done(key);
    }
}

static void socks5_close(struct selector_key *key)
{
    free(key->data);
    close(key->fd);
    active_connections--;
}

static const fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_close = socks5_close,
};

void socks5_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage from;
    socklen_t               from_len = sizeof(from);

    int client = accept(key->fd, (struct sockaddr *)&from, &from_len);
    if (client < 0) {
        return;
    }
    if (selector_fd_set_nio(client) < 0) {
        close(client);
        return;
    }

    struct socks5_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        close(client);
        return;
    }
    buffer_init(&conn->read_buffer, sizeof(conn->raw_read), conn->raw_read);
    buffer_init(&conn->write_buffer, sizeof(conn->raw_write), conn->raw_write);

    conn->stm.initial   = NEG_READ;
    conn->stm.states    = socks5_states;
    conn->stm.max_state = ERROR;
    stm_init(&conn->stm);

    if (selector_register(key->s, client, &socks5_handler, OP_READ, conn) != SELECTOR_SUCCESS) {
        free(conn);
        close(client);
        return;
    }
    active_connections++;
}
