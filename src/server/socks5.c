#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "args.h"
#include "auth.h"
#include "buffer.h"
#include "negotiation.h"
#include "request.h"
#include "socks5.h"
#include "stm.h"

#define SOCKS5_BUFFER_SIZE 8192

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

/* Estados de la conexión SOCKS5. */
enum socks5_state {
    NEG_READ = 0,   /* leyendo/parseando la negociación de métodos */
    NEG_WRITE,      /* escribiendo la respuesta de método (2 bytes) */
    AUTH_READ,      /* leyendo/parseando las credenciales user/pass (RFC 1929) */
    AUTH_WRITE,     /* escribiendo la respuesta de auth (2 bytes) */
    REQ_READ,       /* leyendo/parseando el request */
    REQ_RESOLVE,    /* esperando resolución DNS (hilo getaddrinfo, solo FQDN) */
    REQ_CONNECTING, /* connect() no bloqueante en vuelo (origin fd OP_WRITE) */
    REQ_WRITE,      /* escribiendo la respuesta del request */
    RELAY,          /* relay full-duplex entre cliente y origen */
    DONE,           /* terminal: la conexión terminó, hay que cerrarla */
    ERROR,          /* terminal: error de protocolo o de I/O */
};

/** Estado por conexión: stm + parsers + buffers + estado de conexión/relay. */
struct socks5_conn {
    struct state_machine stm;

    struct negotiation_parser neg;
    struct socks5_auth        auth;
    struct socks5_request     request;

    uint8_t method;      /* método elegido en la negociación */
    uint8_t auth_status; /* resultado de auth, a enviar en AUTH_WRITE */

    /* Selector, fds y teardown ------------------------------------------- */
    fd_selector selector;
    int         client_fd;    /* fd del lado cliente */
    int         origin_fd;    /* fd del lado origen (-1 si no existe) */
    int         references;   /* cuántos fds registrados comparten este conn */

    /* Reaper de inactividad ---------------------------------------------- */
    time_t       last_activity; /* última vez que un handler procesó un evento */
    struct socks5_conn *prev;   /* doubly-linked list para recorrer en el reaper */
    struct socks5_conn *next;

    /* Resolución DNS / retry ------------------------------------------------ */
    struct addrinfo        *resolution; /* resultado de getaddrinfo (FQDN) */
    struct addrinfo        *next_addr;  /* siguiente dirección a probar */
    struct addrinfo         literal_ai; /* entrada sintética para IPv4/IPv6 */
    struct sockaddr_storage literal_sa; /* storage para la dirección literal */
    int                     last_errno; /* errno del último connect fallido */
    uint8_t                 reply_atyp; /* ATYP para BND.ADDR en respuesta OK */
    bool                    connected;  /* true si el connect tuvo éxito */
    pthread_t               resolver_tid;
    bool                    resolver_running;

    /* Relay ----------------------------------------------------------------- */
    bool client_closed;     /* cliente envió EOF */
    bool origin_closed;     /* origen envió EOF */
    bool client_wr_shut;    /* ya se hizo shutdown(client, SHUT_WR) */
    bool origin_wr_shut;    /* ya se hizo shutdown(origin, SHUT_WR) */
    fd_interest client_interest;
    fd_interest origin_interest;

    /* read_buffer: client → origin.  write_buffer: origin → client. */
    struct buffer read_buffer;
    struct buffer write_buffer;
    uint8_t       raw_read[SOCKS5_BUFFER_SIZE];
    uint8_t       raw_write[SOCKS5_BUFFER_SIZE];
};

static size_t active_connections = 0;

/** Lista doblemente enlazada de conexiones activas, para recorrer en el reaper. */
static struct socks5_conn *conn_list = NULL;

/** Tiempo máximo (en segundos) sin actividad para fases de handshake/connect.
 *  Los túneles RELAY establecidos no se cosechan por inactividad. */
#define SOCKS5_INACTIVITY_TIMEOUT 60

/* Inserta un conn al frente de la lista. */
static void conn_list_push(struct socks5_conn *c)
{
    c->prev = NULL;
    c->next = conn_list;
    if (conn_list != NULL) {
        conn_list->prev = c;
    }
    conn_list = c;
}

/* Quita un conn de la lista. */
static void conn_list_remove(struct socks5_conn *c)
{
    if (c->prev != NULL) {
        c->prev->next = c->next;
    } else {
        conn_list = c->next;
    }
    if (c->next != NULL) {
        c->next->prev = c->prev;
    }
    c->prev = c->next = NULL;
}

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

/* ----------------------------------------- forward declarations (connect/relay) */

static const fd_handler socks5_handler;
static unsigned request_connect(struct selector_key *key);

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
 * antes de cerrar. Siempre opera sobre el client_fd, no sobre key->fd (que puede
 * ser el origin_fd si se invoca desde el contexto de conexión al origen). */
static unsigned request_fail(struct selector_key *key, uint8_t rep)
{
    struct socks5_conn *c = key->data;
    c->connected = false;
    fill_request_reply(&c->write_buffer, rep, SOCKS5_ATYP_IPV4);
    if (c->origin_fd != -1) {
        selector_set_interest(key->s, c->origin_fd, OP_NOOP);
    }
    if (selector_set_interest(key->s, c->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQ_WRITE;
}

static void resolver_join_if_running(struct socks5_conn *c)
{
    if (c->resolver_running) {
        pthread_join(c->resolver_tid, NULL);
        c->resolver_running = false;
        c->references--;
    }
}

/* Traduce el errno de un connect() fallido al código REP de SOCKS5 (§6). */
static uint8_t rep_from_errno(int err)
{
    switch (err) {
        case ECONNREFUSED:                  return SOCKS5_REP_CONNECTION_REFUSED;
        case ENETUNREACH:                   return SOCKS5_REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:                  return SOCKS5_REP_HOST_UNREACHABLE;
        case ETIMEDOUT:                     return SOCKS5_REP_TTL_EXPIRED;
        default:                            return SOCKS5_REP_GENERAL_FAILURE;
    }
}

static uint8_t reply_atyp_from_family(int family)
{
    return family == AF_INET6 ? SOCKS5_ATYP_IPV6 : SOCKS5_ATYP_IPV4;
}

/* Arma una addrinfo sintética apuntando a literal_sa para destinos IPv4/IPv6
 * (sin necesidad de getaddrinfo). */
static void build_literal_addr(struct socks5_conn *c)
{
    const struct socks5_request *r = &c->request;
    memset(&c->literal_sa, 0, sizeof(c->literal_sa));
    memset(&c->literal_ai, 0, sizeof(c->literal_ai));

    if (r->atyp == SOCKS5_ATYP_IPV4) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&c->literal_sa;
        sa4->sin_family = AF_INET;
        memcpy(&sa4->sin_addr, r->dst_addr, 4);
        sa4->sin_port = htons(r->dst_port);
        c->literal_ai.ai_family   = AF_INET;
        c->literal_ai.ai_addrlen  = sizeof(*sa4);
    } else {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&c->literal_sa;
        sa6->sin6_family = AF_INET6;
        memcpy(&sa6->sin6_addr, r->dst_addr, 16);
        sa6->sin6_port = htons(r->dst_port);
        c->literal_ai.ai_family   = AF_INET6;
        c->literal_ai.ai_addrlen  = sizeof(*sa6);
    }
    c->literal_ai.ai_socktype = SOCK_STREAM;
    c->literal_ai.ai_protocol = IPPROTO_TCP;
    c->literal_ai.ai_addr     = (struct sockaddr *)&c->literal_sa;
    c->literal_ai.ai_next     = NULL;
    c->next_addr = &c->literal_ai;
}

/* Hilo de resolución DNS: ejecuta getaddrinfo y despierta al selector. */
static void *resolve_run(void *arg)
{
    struct socks5_conn *c = arg;
    const struct socks5_request *r = &c->request;

    /* NUL-terminamos el dominio para getaddrinfo. */
    char host[256];
    memcpy(host, r->dst_addr, r->addr_len);
    host[r->addr_len] = '\0';

    char port[6];
    snprintf(port, sizeof(port), "%u", r->dst_port);

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    int rc = getaddrinfo(host, port, &hints, &c->resolution);
    if (rc != 0) {
        c->resolution = NULL;
    }

    if (selector_notify_block(c->selector, c->client_fd) != SELECTOR_SUCCESS) {
        fprintf(stderr, "socks5: selector_notify_block failed for fd %d\n",
                c->client_fd);
    }
    return NULL;
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

    const struct socks5_request *r = &c->request;
    if (r->cmd != SOCKS5_CMD_CONNECT) {
        printf("socks5: comando no soportado (cmd=%u)\n", r->cmd);
        return request_fail(key, SOCKS5_REP_CMD_NOT_SUPPORTED);
    }

    log_request_dst(r);

    /* IPv4/IPv6 literal: armar addrinfo sintética y conectar directamente. */
    if (r->atyp == SOCKS5_ATYP_IPV4 || r->atyp == SOCKS5_ATYP_IPV6) {
        build_literal_addr(c);
        return request_connect(key);
    }

    /* FQDN: resolver en un hilo aparte. Parquear el cliente sin interés hasta que
     * el hilo complete la resolución y despierte al selector. Se cuenta el hilo
     * como referencia para evitar un use-after-free si la conexión se cierra
     * antes de que el hilo termine (e.g. apagado forzado). */
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    c->references++;
    c->resolver_running = true;
    if (pthread_create(&c->resolver_tid, NULL, resolve_run, c) != 0) {
        c->resolver_running = false;
        c->references--;
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }
    return REQ_RESOLVE;
}

/* -------------------------------------------------------- DNS resolve complete */

static unsigned request_resolve_done(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    resolver_join_if_running(c);

    if (c->resolution == NULL) {
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }
    c->next_addr = c->resolution;
    return request_connect(key);
}

/* -------------------------------------------------------- connect to origin */

static unsigned request_connect_success(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    c->connected = true;
    fill_request_reply(&c->write_buffer, SOCKS5_REP_SUCCESS, c->reply_atyp);
    if (selector_set_interest(key->s, c->origin_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    if (selector_set_interest(key->s, c->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQ_WRITE;
}

/* Intenta conectar al siguiente candidato de la lista de direcciones. Si todos
 * fallan, responde con el error SOCKS5 adecuado. */
static unsigned request_connect(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    while (c->next_addr != NULL) {
        struct addrinfo *ai = c->next_addr;
        c->next_addr = ai->ai_next;

        int fd = socket(ai->ai_family, SOCK_STREAM, 0);
        if (fd < 0) {
            c->last_errno = errno;
            continue;
        }
        if (selector_fd_set_nio(fd) < 0) {
            c->last_errno = errno;
            close(fd);
            continue;
        }

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            /* Conexión inmediata (loopback, etc.). */
            c->origin_fd = fd;
            c->reply_atyp = reply_atyp_from_family(ai->ai_family);
            if (selector_register(key->s, fd, &socks5_handler, OP_NOOP, c) != SELECTOR_SUCCESS) {
                close(fd);
                c->origin_fd = -1;
                return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
            }
            c->references++;
            return request_connect_success(key);
        }
        if (errno == EINPROGRESS) {
            c->origin_fd = fd;
            c->reply_atyp = reply_atyp_from_family(ai->ai_family);
            if (selector_register(key->s, fd, &socks5_handler, OP_WRITE, c) != SELECTOR_SUCCESS) {
                close(fd);
                c->origin_fd = -1;
                return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
            }
            c->references++;
            if (selector_set_interest(key->s, c->client_fd, OP_NOOP) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQ_CONNECTING;
        }
        /* Fallo inmediato de connect: probar la siguiente. */
        c->last_errno = errno;
        close(fd);
    }

    /* Todas las direcciones fallaron. */
    return request_fail(key, rep_from_errno(c->last_errno));
}

/* on_write_ready del origin_fd durante REQ_CONNECTING: el connect() completó
 * (con éxito o con error). */
static unsigned request_connecting(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    int       so_error = 0;
    socklen_t len      = sizeof(so_error);
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        so_error = errno;
    }

    if (so_error == 0) {
        return request_connect_success(key);
    }

    /* Fallo: desregistrar el origin_fd y probar la siguiente dirección. */
    c->last_errno = so_error;
    selector_unregister_fd(key->s, c->origin_fd);
    /* socks5_close decrementó references y cerró el fd */
    c->origin_fd = -1;
    return request_connect(key);
}

/* ----------------------------------------------------------- request write */

static unsigned request_write(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    size_t   pending;
    uint8_t *ptr = buffer_read_ptr(&c->write_buffer, &pending);
    ssize_t  n   = send(c->client_fd, ptr, pending, MSG_NOSIGNAL);
    if (n <= 0) {
        return (n < 0 && would_block(errno)) ? REQ_WRITE : ERROR;
    }
    buffer_read_adv(&c->write_buffer, n);

    if (buffer_can_read(&c->write_buffer)) {
        return REQ_WRITE; /* escritura parcial: falta vaciar el buffer */
    }
    if (!c->connected) {
        return DONE; /* la respuesta de error ya se envió: cerrar */
    }
    /* Éxito: pasar al relay. */
    return RELAY;
}

/* ------------------------------------------------------------------- relay */

/* Recalcula los intereses de ambos fds según el estado de los buffers y los
 * flags de cierre. Devuelve RELAY si hay algo pendiente, o DONE si se acabó. */
static unsigned relay_update(struct socks5_conn *c)
{
    /* Propagar medio-cierre: si un lado envió EOF y ya drenamos el buffer
     * correspondiente, hacer shutdown(SHUT_WR) del otro lado. */
    if (c->client_closed && !buffer_can_read(&c->read_buffer) && !c->origin_wr_shut) {
        shutdown(c->origin_fd, SHUT_WR);
        c->origin_wr_shut = true;
    }
    if (c->origin_closed && !buffer_can_read(&c->write_buffer) && !c->client_wr_shut) {
        shutdown(c->client_fd, SHUT_WR);
        c->client_wr_shut = true;
    }

    /* Si ambas direcciones cerraron y los buffers están vacíos: terminamos. */
    if (c->client_wr_shut && c->origin_wr_shut) {
        return DONE;
    }

    /* Calcular interés del client_fd. */
    fd_interest ci = OP_NOOP;
    if (!c->client_closed && buffer_can_write(&c->read_buffer)) {
        ci = (fd_interest)(ci | OP_READ);
    }
    if (buffer_can_read(&c->write_buffer) && !c->client_wr_shut) {
        ci = (fd_interest)(ci | OP_WRITE);
    }
    if (ci != c->client_interest) {
        if (selector_set_interest(c->selector, c->client_fd, ci) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        c->client_interest = ci;
    }

    /* Calcular interés del origin_fd. */
    fd_interest oi = OP_NOOP;
    if (!c->origin_closed && buffer_can_write(&c->write_buffer)) {
        oi = (fd_interest)(oi | OP_READ);
    }
    if (buffer_can_read(&c->read_buffer) && !c->origin_wr_shut) {
        oi = (fd_interest)(oi | OP_WRITE);
    }
    if (oi != c->origin_interest) {
        if (selector_set_interest(c->selector, c->origin_fd, oi) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        c->origin_interest = oi;
    }

    return RELAY;
}

static void relay_init(const unsigned state, struct selector_key *key)
{
    (void)state;
    struct socks5_conn *c = key->data;
    c->client_closed  = false;
    c->origin_closed  = false;
    c->client_wr_shut = false;
    c->origin_wr_shut = false;
    relay_update(c);
}

static unsigned relay_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    bool from_client = (key->fd == c->client_fd);

    /* Elegir el buffer destino: lectura del cliente va a read_buffer (c→o),
     * lectura del origen va a write_buffer (o→c). */
    struct buffer *dst = from_client ? &c->read_buffer : &c->write_buffer;

    size_t   space;
    uint8_t *ptr = buffer_write_ptr(dst, &space);
    ssize_t  n   = recv(key->fd, ptr, space, 0);

    if (n > 0) {
        buffer_write_adv(dst, n);
        return relay_update(c);
    }
    if (n < 0 && would_block(errno)) {
        return RELAY;
    }
    if (n < 0) {
        return ERROR; /* error real de I/O */
    }
    /* n == 0: EOF del peer. */
    if (from_client) {
        c->client_closed = true;
    } else {
        c->origin_closed = true;
    }
    return relay_update(c);
}

static unsigned relay_write(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    bool to_client = (key->fd == c->client_fd);

    /* Elegir el buffer fuente: escritura al cliente drena write_buffer (o→c),
     * escritura al origen drena read_buffer (c→o). */
    struct buffer *src = to_client ? &c->write_buffer : &c->read_buffer;

    size_t   pending;
    uint8_t *ptr = buffer_read_ptr(src, &pending);
    ssize_t  n   = send(key->fd, ptr, pending, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(src, n);
        return relay_update(c);
    }
    if (n < 0 && would_block(errno)) {
        return RELAY;
    }
    if (n == 0) {
        return RELAY;
    }
    return ERROR;
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
        .state          = REQ_RESOLVE,
        .on_block_ready = request_resolve_done,
    },
    {
        .state          = REQ_CONNECTING,
        .on_write_ready = request_connecting,
    },
    {
        .state          = REQ_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state          = RELAY,
        .on_arrival     = relay_init,
        .on_read_ready  = relay_read,
        .on_write_ready = relay_write,
    },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
    },
};

/* ----------------------------------------------------- selector glue / accept */

/* Desregistra ambos fds (si existen) del selector, lo que provoca el cierre
 * vía socks5_close por cada uno. */
static void socks5_done(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    int cfd = c->client_fd;
    int ofd = c->origin_fd;

    /* Desregistrar ambos; el orden no importa: socks5_close libera el conn solo
     * cuando el último fd se cierra (ref-count). Marcar -1 antes para que
     * socks5_close no vuelva a intentar desregistrar un fd ya cerrado. */
    c->client_fd = -1;
    c->origin_fd = -1;
    if (ofd != -1) {
        selector_unregister_fd(key->s, ofd);
    }
    if (cfd != -1) {
        selector_unregister_fd(key->s, cfd);
    }
}

/* Throttle del reaper: última vez que se recorrió la lista (evita recorrer más
 * de una vez por segundo). A nivel de archivo para que los tests puedan
 * resetearlo entre casos. */
static time_t reap_last_sweep = 0;

/* Cierra conexiones que llevan más de SOCKS5_INACTIVITY_TIMEOUT segundos sin
 * actividad.  Se invoca desde el loop principal después de cada selector_select,
 * así que corre a lo sumo cada select_timeout (10s).  Usa un throttle estático
 * para no recorrer la lista más de una vez por segundo. */
void socks5_reap_idle(fd_selector s)
{
    const time_t now = time(NULL);
    if (now == reap_last_sweep) {
        return;
    }
    reap_last_sweep = now;

    for (struct socks5_conn *c = conn_list; c != NULL; ) {
        struct socks5_conn *nxt = c->next; /* capturar: socks5_done libera c */

        unsigned st = stm_state(&c->stm);
        if (st == REQ_RESOLVE || st == RELAY ||
            now - c->last_activity < SOCKS5_INACTIVITY_TIMEOUT) {
            c = nxt;
            continue;
        }

        struct selector_key key = {
            .s    = s,
            .fd   = c->client_fd,
            .data = c,
        };
        if (st == REQ_CONNECTING) {
            unsigned next = request_fail(&key, SOCKS5_REP_TTL_EXPIRED);
            if (next == ERROR || next == DONE) {
                socks5_done(&key);
            } else {
                c->stm.current = &socks5_states[next];
            }
        } else if (c->origin_fd == -1) {
            socks5_done(&key);
        }
        c = nxt;
    }
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
    c->last_activity = time(NULL);
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

static void socks5_block(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    socks5_advance(key, stm_handler_block(&c->stm, key));
}

static void socks5_close(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    close(key->fd);
    c->references--;
    resolver_join_if_running(c);
    if (c->references <= 0) {
        conn_list_remove(c);
        if (c->resolution != NULL) {
            freeaddrinfo(c->resolution);
        }
        free(c);
        active_connections--;
    }
}

static const fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block,
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

    conn->selector   = key->s;
    conn->client_fd  = client;
    conn->origin_fd  = -1;
    conn->references = 1;

    conn->stm.initial   = NEG_READ;
    conn->stm.states    = socks5_states;
    conn->stm.max_state = ERROR;
    stm_init(&conn->stm);

    if (selector_register(key->s, client, &socks5_handler, OP_READ, conn) != SELECTOR_SUCCESS) {
        free(conn);
        close(client);
        return;
    }
    conn->last_activity = time(NULL);
    conn_list_push(conn);
    active_connections++;
}
