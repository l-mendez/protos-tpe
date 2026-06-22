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

/* Estados de la conexión SOCKS5. Resolución de nombres, conexión al origen y
 * relay de datos no están implementados todavía. */
enum socks5_state {
    NEG_READ = 0, /* leyendo/parseando la negociación de métodos */
    NEG_WRITE,    /* escribiendo la respuesta de método (2 bytes) */
    AUTH_READ,    /* leyendo/parseando las credenciales user/pass (RFC 1929) */
    AUTH_WRITE,   /* escribiendo la respuesta de auth (2 bytes) */
    REQ_READ,     /* leyendo/parseando el request */
    REQ_WRITE,    /* escribiendo la respuesta de error del request */
    DONE,         /* terminal: la conexión terminó, hay que cerrarla */
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
 * por un name == NULL (o llega a MAX_USERS): no hay contador explícito.
 *
 * La comparación es por longitud (memcmp), no strcmp: el usuario y la contraseña
 * son cadenas con longitud explícita (RFC 1929) que podrían contener un 0x00. Se
 * rechazan las credenciales vacías. */
static bool credentials_match(const uint8_t *user, size_t ulen,
                              const uint8_t *pass, size_t plen)
{
    if (configured_users == NULL || ulen == 0 || plen == 0) {
        return false;
    }
    for (int i = 0; i < MAX_USERS && configured_users[i].name != NULL; i++) {
        const char *name = configured_users[i].name;
        const char *pw   = configured_users[i].pass;
        if (strlen(name) == ulen && memcmp(name, user, ulen) == 0) {
            return strlen(pw) == plen && memcmp(pw, pass, plen) == 0;
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

    /* Parsear primero lo que ya está en el buffer: si el cliente encadenó varios
     * mensajes en un mismo segmento, esos bytes ya se consumieron del socket y
     * no generarían otro evento de lectura. Sólo se va al socket si hace falta. */
    neg_state st = negotiation_parser_feed(&c->neg, &c->read_buffer);
    if (st != NEG_DONE && st != NEG_INVALID) {
        int closed = fill_read_buffer(key, &c->read_buffer);
        if (closed != -1) {
            return (unsigned)closed;
        }
        st = negotiation_parser_feed(&c->neg, &c->read_buffer);
    }

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

    auth_state st = auth_parser_feed(&c->auth, &c->read_buffer);
    if (st != AUTH_DONE && st != AUTH_ERROR) {
        int closed = fill_read_buffer(key, &c->read_buffer);
        if (closed != -1) {
            return (unsigned)closed;
        }
        st = auth_parser_feed(&c->auth, &c->read_buffer);
    }

    if (st == AUTH_ERROR) {
        return ERROR;
    }
    if (st != AUTH_DONE) {
        return AUTH_READ; /* lectura parcial: esperar más datos */
    }

    bool ok = credentials_match(c->auth.uname, c->auth.ulen,
                                c->auth.passwd, c->auth.plen);
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

/* Copia el dominio a `dst` reemplazando los bytes no imprimibles por '?': el
 * dominio lo controla el cliente y se vuelca a un log, así que se neutraliza
 * cualquier intento de inyección de caracteres de control. */
static void sanitize_domain(char *dst, size_t cap, const uint8_t *src, size_t n)
{
    size_t i = 0;
    for (; i < n && i + 1 < cap; i++) {
        dst[i] = (src[i] >= 0x20 && src[i] < 0x7f) ? (char)src[i] : '?';
    }
    dst[i] = '\0';
}

static void log_request_dst(const struct socks5_request *r)
{
    if (r->atyp == SOCKS5_ATYP_DOMAIN) {
        char host[256];
        sanitize_domain(host, sizeof(host), r->dst_addr, r->addr_len);
        printf("socks5: CONNECT domain %s:%u\n", host, r->dst_port);
    } else {
        char      host[INET6_ADDRSTRLEN] = "?";
        const int af = (r->atyp == SOCKS5_ATYP_IPV6) ? AF_INET6 : AF_INET;
        inet_ntop(af, r->dst_addr, host, sizeof(host));
        printf("socks5: CONNECT %s %s:%u\n",
               af == AF_INET6 ? "ipv6" : "ipv4", host, r->dst_port);
    }
}

/* Encola la respuesta de error del request (RFC 1928 §6) y pasa a escribirla
 * antes de cerrar, en línea con cómo responden las fases de negociación y auth. */
static unsigned request_fail(struct selector_key *key, uint8_t rep)
{
    struct socks5_conn *c = key->data;
    fill_request_reply(&c->write_buffer, rep);
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQ_WRITE;
}

static unsigned request_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    req_state st = request_parser_feed(&c->request, &c->read_buffer);
    if (st != REQ_DONE && st != REQ_ERROR) {
        int closed = fill_read_buffer(key, &c->read_buffer);
        if (closed != -1) {
            return (unsigned)closed;
        }
        st = request_parser_feed(&c->request, &c->read_buffer);
    }

    if (st == REQ_ERROR) {
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }
    if (st != REQ_DONE) {
        return REQ_READ; /* lectura parcial: esperar más datos */
    }

    /* Sólo se soporta CONNECT (RFC 1928 §4); el resto se rechaza. Resolución de
     * nombres, conexión al origen y relay aún no existen, así que un CONNECT
     * válido se registra y la conexión termina. */
    const struct socks5_request *r = &c->request;
    if (r->cmd != SOCKS5_CMD_CONNECT) {
        printf("socks5: comando no soportado (cmd=%u)\n", r->cmd);
        return request_fail(key, SOCKS5_REP_CMD_NOT_SUPPORTED);
    }

    log_request_dst(r);
    return DONE;
}

static unsigned request_write(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    size_t   pending;
    uint8_t *ptr = buffer_read_ptr(&c->write_buffer, &pending);
    ssize_t  n   = send(key->fd, ptr, pending, MSG_NOSIGNAL);
    if (n <= 0) {
        return (n < 0 && would_block(errno)) ? REQ_WRITE : ERROR;
    }
    buffer_read_adv(&c->write_buffer, n);

    if (buffer_can_read(&c->write_buffer)) {
        return REQ_WRITE; /* escritura parcial: falta vaciar el buffer */
    }
    return DONE; /* la respuesta de error ya se envió: cerrar */
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
        .state          = REQ_WRITE,
        .on_write_ready = request_write,
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

static bool is_read_state(unsigned st)
{
    return st == NEG_READ || st == AUTH_READ || st == REQ_READ;
}

/* Tras procesar un evento, una fase puede haber dejado en el buffer bytes que ya
 * pertenecen a la fase siguiente (cliente que encadenó mensajes en un mismo
 * segmento). El selector es level-triggered sobre el socket y esos bytes ya se
 * consumieron de él, así que no habría otro evento de lectura para procesarlos:
 * se vuelve a correr el handler de lectura mientras queden datos en el buffer. */
static void socks5_advance(struct selector_key *key, unsigned st)
{
    struct socks5_conn *c = key->data;
    while (is_read_state(st) && buffer_can_read(&c->read_buffer)) {
        st = stm_handler_read(&c->stm, key);
    }
    if (st == ERROR || st == DONE) {
        socks5_done(key);
    }
}

static void socks5_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    socks5_advance(key, stm_handler_read(&c->stm, key));
}

static void socks5_write(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    socks5_advance(key, stm_handler_write(&c->stm, key));
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

    struct socks5_conn *conn = calloc(1, sizeof(*conn));
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
