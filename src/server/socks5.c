#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include "metrics.h"
#include "negotiation.h"
#include "netutils.h"
#include "access_log.h"
#include "config.h"
#include "request.h"
#include "socks5.h"
#include "socks5_internal.h"
#include "stm.h"
#include "users.h"

#define SOCKS5_BUFFER_SIZE 4096

/* Linux evita el SIGPIPE en send() con esta flag; macOS no la define y lo
 * resuelve ignorando SIGPIPE en el arranque, así que aquí degrada a 0. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

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

/** Lista doblemente enlazada de conexiones activas, para recorrer en el reaper. */
static struct socks5_conn *conn_list = NULL;

/** Métricas del proceso, inyectadas por main() vía socks5_set_metrics(). */
static struct Metrics *metrics = NULL;

/** fd del listener socks5 desarmado por agotamiento de descriptores (EMFILE/ENFILE);
 * -1 si no hay ninguno pausado. Se re-arma al liberarse una conexión. */
static int accept_paused_fd = -1;

/** Timeout por defecto (en segundos) cuando no hay configuración runtime. */
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

static void conn_mark_inactive(struct socks5_conn *c)
{
    if (c->active_counted) {
        c->active_counted = false;
        metrics_connection_closed(metrics);
    }
}

void socks5_conn_free_if_unreferenced(struct socks5_conn *c)
{
    if (c->references > 0) {
        return;
    }
    conn_mark_inactive(c);
    conn_list_remove(c);
    if (c->resolution != NULL) {
        freeaddrinfo(c->resolution);
    }
    free(c->raw_read);
    free(c->raw_write);
    free(c);
}

/* Almacén de usuarios del proxy, inyectado por main() vía socks5_set_users(). Es
 * la fuente de verdad en runtime: el protocolo de monitoreo lo modifica en
 * caliente y acá sólo se lo lee. */
static struct Users *users_store = NULL;

void socks5_set_users(struct Users *users)
{
    users_store = users;
}

void socks5_set_metrics(struct Metrics *m)
{
    metrics = m;
}

/* Registro de accesos, inyectado por main() vía socks5_set_access_log(). NULL si
 * el registro está deshabilitado. */
static struct AccessLog *access_log = NULL;

void socks5_set_access_log(struct AccessLog *l)
{
    access_log = l;
}

/* Configuración runtime, inyectada por main() vía socks5_set_config(). NULL =>
 * usar los defaults de compilación. */
static struct Config *config = NULL;

void socks5_set_config(struct Config *cfg)
{
    config = cfg;
}

/* Valor efectivo de cada parámetro: el de config si está inyectada, o el default
 * de compilación en su ausencia (p.ej. en tests unitarios). */
static uint32_t effective_conn_timeout(void)
{
    return config != NULL ? config_conn_timeout(config) : SOCKS5_INACTIVITY_TIMEOUT;
}

static uint32_t effective_io_buffer_size(void)
{
    return config != NULL ? config_io_buffer_size(config) : SOCKS5_BUFFER_SIZE;
}

/* true si hay al menos un usuario cargado: en ese caso la autenticación
 * user/pass es obligatoria durante la negociación. */
static bool auth_required(void)
{
    return users_store != NULL && users_count(users_store) > 0;
}

size_t socks5_active_connections(void)
{
    return metrics != NULL ? metrics->active_connections : 0;
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

typedef int (*parser_feed_fn)(struct socks5_conn *c, struct buffer *b);

static int feed_negotiation(struct socks5_conn *c, struct buffer *b)
{
    return negotiation_parser_feed(&c->neg, b);
}

static int feed_auth(struct socks5_conn *c, struct buffer *b)
{
    return auth_parser_feed(&c->auth, b);
}

static int feed_request(struct socks5_conn *c, struct buffer *b)
{
    return request_parser_feed(&c->request, b);
}

/* Alimenta primero los bytes ya bufferizados y sólo lee del socket si el
 * parser todavía necesita datos. Devuelve false cuando la lectura cerró o
 * falló, dejando en state el estado terminal de la conexión. */
static bool feed_parser(struct selector_key *key, parser_feed_fn feed,
                        int done, int invalid, int *state)
{
    struct socks5_conn *c = key->data;
    *state = feed(c, &c->read_buffer);
    if (*state == done || *state == invalid) {
        return true;
    }

    int closed = fill_read_buffer(key, &c->read_buffer);
    if (closed != -1) {
        *state = closed;
        return false;
    }
    *state = feed(c, &c->read_buffer);
    return true;
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
    int st;
    if (!feed_parser(key, feed_negotiation, NEG_DONE, NEG_INVALID, &st)) {
        return (unsigned)st;
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

    int st;
    if (!feed_parser(key, feed_auth, AUTH_DONE, AUTH_ERROR, &st)) {
        return (unsigned)st;
    }

    if (st == AUTH_ERROR) {
        return ERROR;
    }
    if (st != AUTH_DONE) {
        return AUTH_READ; /* lectura parcial: esperar más datos */
    }

    bool ok = users_validate(users_store, c->auth.uname, c->auth.ulen,
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

/* Formatea el destino como "host:puerto" y devuelve su tipo para el log. */
static const char *format_request_dst(char *out, size_t cap,
                                      const struct socks5_request *r)
{
    char host[256] = "?";
    const char *kind;

    if (r->atyp == SOCKS5_ATYP_DOMAIN) {
        kind = "domain";
        sanitize_domain(host, sizeof(host), r->dst_addr, r->addr_len);
    } else {
        const bool ipv6 = r->atyp == SOCKS5_ATYP_IPV6;
        kind = ipv6 ? "ipv6" : "ipv4";
        const int af = ipv6 ? AF_INET6 : AF_INET;
        inet_ntop(af, r->dst_addr, host, sizeof(host));
    }
    snprintf(out, cap, "%s:%u", host, r->dst_port);
    return kind;
}

static void log_request_dst(const struct socks5_request *r)
{
    char dst[300];
    const char *kind = format_request_dst(dst, sizeof(dst), r);
    printf("socks5: CONNECT %s %s\n", kind, dst);
}

/* Traduce el código REP de SOCKS5 (§6) al token de resultado del log (§7). */
static const char *result_token(uint8_t rep)
{
    switch (rep) {
        case SOCKS5_REP_SUCCESS:            return "OK";
        case SOCKS5_REP_CONNECTION_REFUSED: return "CONN-REFUSED";
        case SOCKS5_REP_HOST_UNREACHABLE:   return "HOST-UNREACH";
        case SOCKS5_REP_NETWORK_UNREACHABLE:return "NET-UNREACH";
        case SOCKS5_REP_TTL_EXPIRED:        return "TTL-EXPIRED";
        case SOCKS5_REP_CMD_NOT_SUPPORTED:  return "CMD-NOT-SUPPORTED";
        default:                            return "GENERAL-FAILURE";
    }
}

/* Anexa un registro de acceso para este CONNECT. No-op si el log no está
 * inyectado. El usuario es el autenticado (o "-" si fue anónimo); se neutralizan
 * bytes no imprimibles y espacios para que la línea siga siendo parseable. */
static void socks5_log_access(struct socks5_conn *c, const char *result)
{
    if (access_log == NULL) {
        return;
    }
    char user[USERS_NAME_MAX + 1];
    if (c->method == SOCKS5_METHOD_USERPASS && c->auth.ulen > 0) {
        size_t n = c->auth.ulen;
        if (n > USERS_NAME_MAX) {
            n = USERS_NAME_MAX;
        }
        for (size_t i = 0; i < n; i++) {
            uint8_t ch = c->auth.uname[i];
            user[i] = (ch > 0x20 && ch < 0x7f) ? (char)ch : '?';
        }
        user[n] = '\0';
    } else {
        user[0] = '-';
        user[1] = '\0';
    }
    char dst[300];
    (void)format_request_dst(dst, sizeof(dst), &c->request);
    access_log_record(access_log, user, dst, result);
}

/* Encola la respuesta de error del request (RFC 1928 §6) y pasa a escribirla
 * antes de cerrar. Siempre opera sobre el client_fd, no sobre key->fd (que puede
 * ser el origin_fd si se invoca desde el contexto de conexión al origen). */
static unsigned request_fail(struct selector_key *key, uint8_t rep)
{
    struct socks5_conn *c = key->data;
    c->connected = false;
    /* Registrar sólo si el request llegó a parsearse (hay destino válido); un
     * error de parseo no representa un acceso a un destino conocido. */
    if (request_done(&c->request)) {
        socks5_log_access(c, result_token(rep));
    }
    fill_request_reply(&c->write_buffer, rep, SOCKS5_ATYP_IPV4);
    if (c->origin_fd != -1) {
        int ofd = c->origin_fd;
        c->origin_fd = -1;
        selector_unregister_fd(key->s, ofd);
    }
    if (selector_set_interest(key->s, c->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQ_WRITE;
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

static unsigned request_read(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    int st;
    if (!feed_parser(key, feed_request, REQ_DONE, REQ_ERROR, &st)) {
        return (unsigned)st;
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

    /* FQDN: resolver en el pool acotado. Parquear el cliente sin interés hasta
     * que el worker complete la resolución y despierte al selector. */
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
        return ERROR;
    }

    char host[256];
    memcpy(host, r->dst_addr, r->addr_len);
    host[r->addr_len] = '\0';

    char port[6];
    snprintf(port, sizeof(port), "%u", r->dst_port);

    if (!socks5_resolver_queue_job(c, host, port)) {
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }
    return REQ_RESOLVE;
}

/* -------------------------------------------------------- DNS resolve complete */

static unsigned request_resolve_done(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    if (!socks5_resolver_take_completed(c)) {
        return REQ_RESOLVE;
    }

    if (c->resolution == NULL) {
        /* getaddrinfo no distingue causas que mapeen limpio a un REP de §6. */
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }
    c->next_addr = c->resolution;
    return request_connect(key);
}

/* -------------------------------------------------------- connect to origin */

static unsigned request_connect_success(struct selector_key *key)
{
    struct socks5_conn *c = key->data;

    struct sockaddr_storage local;
    socklen_t               local_len = sizeof(local);
    if (getsockname(c->origin_fd, (struct sockaddr *)&local, &local_len) < 0) {
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }

    c->connected = true;
    if (!fill_request_reply_addr(&c->write_buffer, SOCKS5_REP_SUCCESS,
                                 (const struct sockaddr *)&local)) {
        return request_fail(key, SOCKS5_REP_GENERAL_FAILURE);
    }
    socks5_log_access(c, "OK");
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
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            /* Conexión inmediata (loopback, etc.). */
            c->origin_fd = fd;
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
    buffer_compact(&c->read_buffer);
    buffer_compact(&c->write_buffer);

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
    /* on_arrival es void y no puede devolver un estado: si armar los intereses de
     * los dos fds falla, se marca el conn para que socks5_advance lo cierre en
     * vez de dejarlo colgado en RELAY hasta que lo coseche el reaper. */
    if (relay_update(c) == ERROR) {
        c->arrival_error = true;
    }
}

static unsigned relay_flush(struct socks5_conn *c, bool to_client)
{
    /* Escritura al cliente drena write_buffer (o->c); escritura al origen drena
     * read_buffer (c->o). */
    struct buffer *src = to_client ? &c->write_buffer : &c->read_buffer;
    int fd = to_client ? c->client_fd : c->origin_fd;

    while (buffer_can_read(src)) {
        size_t   pending;
        uint8_t *ptr = buffer_read_ptr(src, &pending);
        ssize_t  n   = send(fd, ptr, pending, MSG_NOSIGNAL);

        if (n > 0) {
            buffer_read_adv(src, n);
        } else if (n < 0 && would_block(errno)) {
            return RELAY;
        } else if (n == 0) {
            return RELAY;
        } else {
            return ERROR;
        }
    }
    return RELAY;
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
        if (from_client) {
            metrics_bytes_client_to_origin(metrics, (size_t) n);
        } else {
            metrics_bytes_origin_to_client(metrics, (size_t) n);
        }
        unsigned st = relay_flush(c, !from_client);
        if (st == ERROR) {
            return ERROR;
        }
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

    unsigned st = relay_flush(c, to_client);
    if (st == ERROR) {
        return ERROR;
    }
    return relay_update(c);
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

/* Reloj monotónico (en segundos) para los timeouts del reaper y los sellos de
 * actividad. A diferencia de time(NULL), es inmune a saltos del reloj de pared
 * (NTP, ajuste de admin): un salto hacia adelante no cosecharía de golpe todos
 * los túneles vivos, ni uno hacia atrás dejaría de cosechar a los muertos. */
static time_t monotonic_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static bool idle_timeout_expired(time_t now, time_t last_activity, time_t timeout)
{
    return now - last_activity > timeout;
}

/* Throttle del reaper: última vez que se recorrió la lista (evita recorrer más
 * de una vez por segundo). A nivel de archivo para que los tests puedan
 * resetearlo entre casos. */
static time_t reap_last_sweep = 0;

/* Cierra conexiones que superan el conn_timeout vigente sin actividad. Se invoca
 * desde el loop principal después de cada selector_select, así que corre a lo
 * sumo cada select_timeout (10s). Usa un throttle estático para no recorrer la
 * lista más de una vez por segundo; eso puede demorar hasta 1s el fallback de
 * resoluciones completadas, aceptable porque sólo actúa si la notificación
 * primaria (selector_notify_block) falló. */
void socks5_reap_idle(fd_selector s)
{
    const time_t now = monotonic_now();
    if (now == reap_last_sweep) {
        return;
    }
    reap_last_sweep = now;

    for (struct socks5_conn *c = conn_list; c != NULL; ) {
        struct socks5_conn *nxt = c->next; /* capturar: socks5_done libera c */

        unsigned st = stm_state(&c->stm);
        struct selector_key key = {
            .s    = s,
            .fd   = c->client_fd,
            .data = c,
        };

        if (st == REQ_RESOLVE && socks5_resolver_is_completed(c)) {
            unsigned next = request_resolve_done(&key);
            if (next == ERROR || next == DONE) {
                socks5_done(&key);
            } else {
                c->last_activity = now;
                c->stm.current = &socks5_states[next];
            }
            c = nxt;
            continue;
        }

        const time_t timeout = (time_t)effective_conn_timeout();
        if (!idle_timeout_expired(now, c->last_activity, timeout)) {
            c = nxt;
            continue;
        }

        if (st == REQ_CONNECTING) {
            unsigned next = request_fail(&key, SOCKS5_REP_TTL_EXPIRED);
            if (next == ERROR || next == DONE) {
                socks5_done(&key);
            } else {
                c->last_activity = now;
                c->stm.current = &socks5_states[next];
            }
        } else if (st == REQ_RESOLVE) {
            socks5_resolver_cancel_conn(c);
            if (c->client_fd == -1) {
                conn_mark_inactive(c);
                socks5_conn_free_if_unreferenced(c);
            } else {
                unsigned next = request_fail(&key, SOCKS5_REP_GENERAL_FAILURE);
                if (next == ERROR || next == DONE) {
                    socks5_done(&key);
                } else {
                    c->last_activity = now;
                    c->stm.current = &socks5_states[next];
                }
            }
        } else {
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
    c->last_activity = monotonic_now();
    while (is_read_state(st) && buffer_can_read(&c->read_buffer)) {
        st = stm_handler_read(&c->stm, key);
    }
    if (st == ERROR || st == DONE || c->arrival_error) {
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
    if (stm_state(&c->stm) != REQ_RESOLVE) {
        return;
    }
    socks5_advance(key, stm_handler_block(&c->stm, key));
}

static void socks5_close(struct selector_key *key)
{
    struct socks5_conn *c = key->data;
    close(key->fd);
    if (key->fd == c->client_fd) {
        c->client_fd = -1;
    } else if (key->fd == c->origin_fd) {
        c->origin_fd = -1;
    }
    c->references--;

    if (c->client_fd == -1 && c->origin_fd == -1) {
        conn_mark_inactive(c);
        socks5_resolver_cancel_conn(c);
    } else {
        /* No-op si el job sigue en vuelo o ya no existe; reclama si completó. */
        socks5_resolver_take_completed(c);
    }
    socks5_conn_free_if_unreferenced(c);

    socks5_retry_accept(key->s);
}

void socks5_retry_accept(fd_selector s)
{
    if (s != NULL && accept_paused_fd >= 0 &&
        selector_set_interest(s, accept_paused_fd, OP_READ) == SELECTOR_SUCCESS) {
        accept_paused_fd = -1;
    }
}

void socks5_forget_paused_listener(int fd)
{
    if (accept_paused_fd == fd) {
        accept_paused_fd = -1;
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
    /* Drenar toda la cola de aceptación: el listener es no bloqueante, así que
     * accept() devuelve -1 (EAGAIN) cuando no quedan conexiones pendientes. */
    for (;;) {
        struct sockaddr_storage from;
        socklen_t               from_len = sizeof(from);

        int client = accept(key->fd, (struct sockaddr *)&from, &from_len);
        if (client < 0) {
            /* EAGAIN/EWOULDBLOCK: cola drenada, terminar normalmente. EMFILE/ENFILE:
             * descriptores agotados; desarmar el listener para no reintentar accept()
             * en cada ciclo del selector (busy-spin al ~100% de CPU). Se re-arma
             * cuando una conexión SOCKS5 o management libera un fd. */
            if (errno == EMFILE || errno == ENFILE) {
                selector_set_interest_key(key, OP_NOOP);
                accept_paused_fd = key->fd;
            }
            return;
        }

        /* Tope blando de conexiones concurrentes: si ya se alcanzó, rechazar la
         * nueva sin registrarla. */
        if (config != NULL && metrics != NULL &&
            metrics->active_connections >= config_max_connections(config)) {
            close(client);
            continue;
        }

        if (selector_fd_set_nio(client) < 0) {
            close(client);
            continue;
        }

        /* Nagle + delayed ACK agrega ~40ms por ida y vuelta en el relay;
         * deshabilitarlo no es crítico, así que se ignora el resultado. */
        (void)setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));

        struct socks5_conn *conn = calloc(1, sizeof(*conn));
        if (conn == NULL) {
            close(client);
            continue;
        }

        /* Buffers de relay en el heap, con el tamaño vigente (io_buffer_size). */
        const size_t bufsize = effective_io_buffer_size();
        conn->raw_read  = malloc(bufsize);
        conn->raw_write = malloc(bufsize);
        if (conn->raw_read == NULL || conn->raw_write == NULL) {
            free(conn->raw_read);
            free(conn->raw_write);
            free(conn);
            close(client);
            continue;
        }
        buffer_init(&conn->read_buffer, bufsize, conn->raw_read);
        buffer_init(&conn->write_buffer, bufsize, conn->raw_write);

        conn->selector   = key->s;
        conn->client_fd  = client;
        conn->origin_fd  = -1;
        conn->references = 1;
        conn->active_counted = true;

        conn->stm.initial   = NEG_READ;
        conn->stm.states    = socks5_states;
        conn->stm.max_state = ERROR;
        stm_init(&conn->stm);

        if (selector_register(key->s, client, &socks5_handler, OP_READ, conn) != SELECTOR_SUCCESS) {
            free(conn->raw_read);
            free(conn->raw_write);
            free(conn);
            close(client);
            continue;
        }
        conn->last_activity = monotonic_now();
        conn_list_push(conn);
        metrics_connection_opened(metrics);
    }
}
