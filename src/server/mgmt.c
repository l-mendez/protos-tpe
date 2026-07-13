#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mgmt.h"
#include "mgmt_parser.h"

/* Linux evita el SIGPIPE en send() con esta flag; macOS no la define y lo
 * resuelve ignorando SIGPIPE en el arranque, así que aquí degrada a 0. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MGMT_OUTPUT_BUFFER_SIZE ((MGMT_LOG_MAX_LINES * ACCESS_LOG_LINE_MAX) + 4096)

struct mgmt_conn {
    int                 fd;
    struct mgmt_session session;
    struct mgmt_parser  parser;
    buffer              read_buffer;
    buffer              write_buffer;
    uint8_t             raw_read[MGMT_LINE_MAX];
    uint8_t             raw_write[MGMT_OUTPUT_BUFFER_SIZE];
    bool                close_after_write;
};

static const struct mgmt_deps *global_deps = NULL;
static size_t                  active_mgmt_connections = 0;

static void mgmt_read(struct selector_key *key);
static void mgmt_write(struct selector_key *key);
static void mgmt_close(struct selector_key *key);

static const fd_handler mgmt_handler = {
    .handle_read  = mgmt_read,
    .handle_write = mgmt_write,
    .handle_close = mgmt_close,
};

static inline int would_block(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

/* ------------------------------------------------------------ admin creds */

void admin_init(struct AdminCreds *a, const char *name, const char *pass)
{
    snprintf(a->name, sizeof(a->name), "%s", name != NULL ? name : "");
    snprintf(a->pass, sizeof(a->pass), "%s", pass != NULL ? pass : "");
}

bool admin_check(const struct AdminCreds *a, const char *name, const char *pass)
{
    if (a->name[0] == '\0') {
        return false; /* sin admin configurado: nadie puede autenticarse */
    }
    return strcmp(a->name, name) == 0 && strcmp(a->pass, pass) == 0;
}

bool admin_set_pass(struct AdminCreds *a, const char *pass)
{
    if (pass == NULL || pass[0] == '\0' || strlen(pass) >= sizeof(a->pass)) {
        return false;
    }
    snprintf(a->pass, sizeof(a->pass), "%s", pass);
    return true;
}

void mgmt_session_init(struct mgmt_session *s, const struct mgmt_deps *deps)
{
    s->deps          = deps;
    s->authenticated = false;
}

void mgmt_set_deps(const struct mgmt_deps *deps)
{
    global_deps = deps;
}

size_t mgmt_active_connections(void)
{
    return active_mgmt_connections;
}

/* ------------------------------------------------------------ helpers */

/* Comparación de comando, case-insensitive (ASCII). */
static bool ieq(const char *a, const char *b)
{
    for (; *a != '\0' && *b != '\0'; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return false;
    }
    return *a == *b;
}

/* Escribe una respuesta formateada en el buffer (acotada a una línea larga). */
static void out_printf(buffer *b, const char *fmt, ...)
{
    char tmp[ACCESS_LOG_LINE_MAX + 128];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) {
        return;
    }
    size_t   want = (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1;
    size_t   space;
    uint8_t *p = buffer_write_ptr(b, &space);
    if (want > space) {
        want = space; /* sin lugar: truncar (el buffer se dimensiona holgado) */
    }
    memcpy(p, tmp, want);
    buffer_write_adv(b, want);
}

/* Parsea un entero decimal sin signo. false si vacío, no numérico o desborda. */
static bool parse_u32(const char *s, uint32_t *out)
{
    if (s == NULL || *s == '\0') {
        return false;
    }
    char         *end = NULL;
    unsigned long v   = strtoul(s, &end, 10);
    if (*end != '\0' || v > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

/* ------------------------------------------------------------ commands */

static void cmd_metrics(struct mgmt_session *s, buffer *out)
{
    const struct Metrics *m = s->deps->metrics;
    out_printf(out, "+OK 7\n");
    out_printf(out, "active_connections %zu\n", m->active_connections);
    out_printf(out, "historical_connections %llu\n",
               (unsigned long long)m->historical_connections);
    out_printf(out, "max_active_connections %zu\n", m->max_active_connections);
    out_printf(out, "bytes_client_to_origin %llu\n",
               (unsigned long long)m->bytes_client_to_origin);
    out_printf(out, "bytes_origin_to_client %llu\n",
               (unsigned long long)m->bytes_origin_to_client);
    out_printf(out, "total_bytes %llu\n",
               (unsigned long long)(m->bytes_client_to_origin + m->bytes_origin_to_client));
    out_printf(out, "users_count %zu\n", users_count(s->deps->users));
}

static void cmd_list_users(struct mgmt_session *s, buffer *out)
{
    size_t n = users_count(s->deps->users);
    out_printf(out, "+OK %zu\n", n);
    for (size_t i = 0; i < n; i++) {
        out_printf(out, "%s\n", users_name_at(s->deps->users, i));
    }
}

static void cmd_add_user(struct mgmt_session *s, int argc, char **argv, buffer *out)
{
    if (argc != 3) {
        out_printf(out, "-ERR invalid\n");
    } else if (users_exists(s->deps->users, argv[1])) {
        out_printf(out, "-ERR user exists\n");
    } else if (users_count(s->deps->users) >= USERS_MAX) {
        out_printf(out, "-ERR store full\n");
    } else if (users_add(s->deps->users, argv[1], argv[2])) {
        out_printf(out, "+OK user added\n");
    } else {
        out_printf(out, "-ERR invalid\n"); /* vacío o demasiado largo */
    }
}

static void cmd_del_user(struct mgmt_session *s, int argc, char **argv, buffer *out)
{
    if (argc != 2) {
        out_printf(out, "-ERR invalid\n");
    } else if (users_del(s->deps->users, argv[1])) {
        out_printf(out, "+OK user removed\n");
    } else {
        out_printf(out, "-ERR no such user\n");
    }
}

static void cmd_get_config(struct mgmt_session *s, buffer *out)
{
    const struct Config *cfg = s->deps->config;
    out_printf(out, "+OK 3\n");
    out_printf(out, "conn_timeout %u\n", config_conn_timeout(cfg));
    out_printf(out, "io_buffer_size %u\n", config_io_buffer_size(cfg));
    out_printf(out, "max_connections %u\n", config_max_connections(cfg));
}

static void cmd_set(struct mgmt_session *s, int argc, char **argv, buffer *out)
{
    if (argc != 3) {
        out_printf(out, "-ERR invalid\n");
        return;
    }
    const char *key = argv[1];
    bool known = ieq(key, "conn_timeout") || ieq(key, "io_buffer_size") ||
                 ieq(key, "max_connections");
    if (!known) {
        out_printf(out, "-ERR unknown key\n");
        return;
    }
    uint32_t v;
    if (!parse_u32(argv[2], &v)) {
        out_printf(out, "-ERR invalid value\n");
        return;
    }
    struct Config *cfg = s->deps->config;
    bool ok = ieq(key, "conn_timeout")   ? config_set_conn_timeout(cfg, v)
            : ieq(key, "io_buffer_size") ? config_set_io_buffer_size(cfg, v)
                                         : config_set_max_connections(cfg, v);
    if (ok) {
        out_printf(out, "+OK %s = %u\n", key, v);
    } else {
        out_printf(out, "-ERR invalid value\n");
    }
}

static void cmd_log(struct mgmt_session *s, int argc, char **argv, buffer *out)
{
    if (argc > 2) {
        out_printf(out, "-ERR invalid\n");
        return;
    }
    uint32_t n = 10; /* default */
    if (argc == 2 && !parse_u32(argv[1], &n)) {
        out_printf(out, "-ERR invalid\n");
        return;
    }
    if (n > MGMT_LOG_MAX_LINES) {
        n = MGMT_LOG_MAX_LINES;
    }
    static char lines[MGMT_LOG_MAX_LINES][ACCESS_LOG_LINE_MAX];
    size_t got = access_log_tail(s->deps->access_log, n, lines, MGMT_LOG_MAX_LINES);
    out_printf(out, "+OK %zu\n", got);
    for (size_t i = 0; i < got; i++) {
        out_printf(out, "%s\n", lines[i]);
    }
}

static void cmd_help(buffer *out)
{
    out_printf(out, "+OK 10\n");
    out_printf(out, "AUTH <user> <pass>\n");
    out_printf(out, "METRICS\n");
    out_printf(out, "LIST-USERS\n");
    out_printf(out, "ADD-USER <user> <pass>\n");
    out_printf(out, "DEL-USER <user>\n");
    out_printf(out, "GET-CONFIG\n");
    out_printf(out, "SET <key> <value>\n");
    out_printf(out, "LOG [n]\n");
    out_printf(out, "PASSWD <newpass>\n");
    out_printf(out, "QUIT\n");
}

/* ------------------------------------------------------------ dispatch */

bool mgmt_handle_line(struct mgmt_session *s, char *line, buffer *out)
{
    char *argv[5];
    int   argc = mgmt_tokenize(line, argv, 5);

    if (argc == 0) {
        out_printf(out, "-ERR unknown command\n");
        return false;
    }
    const char *cmd = argv[0];

    /* Comandos disponibles en cualquier estado. */
    if (ieq(cmd, "QUIT")) {
        out_printf(out, "+OK bye\n");
        return true;
    }
    if (ieq(cmd, "HELP")) {
        cmd_help(out);
        return false;
    }
    if (ieq(cmd, "AUTH")) {
        if (s->authenticated) {
            out_printf(out, "-ERR already authenticated\n");
        } else if (argc != 3) {
            out_printf(out, "-ERR invalid\n");
        } else if (admin_check(s->deps->admin, argv[1], argv[2])) {
            s->authenticated = true;
            out_printf(out, "+OK authenticated\n");
        } else {
            out_printf(out, "-ERR bad credentials\n");
        }
        return false;
    }

    /* El resto requiere autenticación. */
    if (!s->authenticated) {
        out_printf(out, "-ERR not authenticated\n");
        return false;
    }

    if (ieq(cmd, "METRICS"))         cmd_metrics(s, out);
    else if (ieq(cmd, "LIST-USERS")) cmd_list_users(s, out);
    else if (ieq(cmd, "ADD-USER"))   cmd_add_user(s, argc, argv, out);
    else if (ieq(cmd, "DEL-USER"))   cmd_del_user(s, argc, argv, out);
    else if (ieq(cmd, "GET-CONFIG")) cmd_get_config(s, out);
    else if (ieq(cmd, "SET"))        cmd_set(s, argc, argv, out);
    else if (ieq(cmd, "LOG"))        cmd_log(s, argc, argv, out);
    else if (ieq(cmd, "PASSWD")) {
        if (argc != 2) {
            out_printf(out, "-ERR invalid\n");
        } else if (admin_set_pass(s->deps->admin, argv[1])) {
            out_printf(out, "+OK password changed\n");
        } else {
            out_printf(out, "-ERR invalid\n");
        }
    } else {
        out_printf(out, "-ERR unknown command\n");
    }
    return false;
}

/* ----------------------------------------------------- selector glue / accept */

static bool has_output(struct mgmt_conn *c)
{
    return buffer_can_read(&c->write_buffer);
}

static void process_input_lines(struct mgmt_conn *c)
{
    while (buffer_can_read(&c->read_buffer) && buffer_can_write(&c->write_buffer)) {
        mgmt_line_state st = mgmt_parser_feed(&c->parser, &c->read_buffer);
        if (st == MGMT_LINE_INCOMPLETE) {
            break;
        }
        if (st == MGMT_LINE_READY) {
            if (mgmt_handle_line(&c->session, c->parser.line, &c->write_buffer)) {
                c->close_after_write = true;
            }
        } else if (st == MGMT_LINE_TOO_LONG) {
            out_printf(&c->write_buffer, "-ERR line too long\n");
        } else {
            out_printf(&c->write_buffer, "-ERR invalid\n");
        }
        mgmt_parser_reset(&c->parser);
        if (c->close_after_write) {
            break;
        }
    }
}

static bool mgmt_flush(struct selector_key *key)
{
    struct mgmt_conn *c = key->data;

    while (has_output(c)) {
        size_t   pending;
        uint8_t *ptr = buffer_read_ptr(&c->write_buffer, &pending);
        ssize_t  n   = send(key->fd, ptr, pending, MSG_NOSIGNAL);
        if (n > 0) {
            buffer_read_adv(&c->write_buffer, n);
        } else if (n < 0 && would_block(errno)) {
            return true;
        } else {
            selector_unregister_fd(key->s, key->fd);
            return false;
        }
    }
    return true;
}

static void mgmt_read(struct selector_key *key)
{
    struct mgmt_conn *c = key->data;

    if (!buffer_can_write(&c->write_buffer)) {
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    buffer_compact(&c->read_buffer);

    size_t   space;
    uint8_t *ptr = buffer_write_ptr(&c->read_buffer, &space);
    ssize_t  n   = recv(key->fd, ptr, space, 0);
    if (n > 0) {
        buffer_write_adv(&c->read_buffer, n);
        process_input_lines(c);
        if (!mgmt_flush(key)) {
            return;
        }
        if (c->close_after_write && !has_output(c)) {
            selector_unregister_fd(key->s, key->fd);
            return;
        }
        selector_set_interest_key(key, has_output(c) ? OP_WRITE : OP_READ);
        return;
    }
    if (n < 0 && would_block(errno)) {
        return;
    }
    selector_unregister_fd(key->s, key->fd);
}

static void mgmt_write(struct selector_key *key)
{
    struct mgmt_conn *c = key->data;

    if (!mgmt_flush(key)) {
        return;
    }

    if (has_output(c)) {
        selector_set_interest_key(key, OP_WRITE);
        return;
    }
    if (c->close_after_write) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    process_input_lines(c);
    if (has_output(c)) {
        selector_set_interest_key(key, OP_WRITE);
    } else {
        selector_set_interest_key(key, OP_READ);
    }
}

static void mgmt_close(struct selector_key *key)
{
    struct mgmt_conn *c = key->data;

    close(key->fd);
    if (active_mgmt_connections > 0) {
        active_mgmt_connections--;
    }
    free(c);
}

void mgmt_passive_accept(struct selector_key *key)
{
    if (global_deps == NULL) {
        return;
    }

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

    struct mgmt_conn *conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
        close(client);
        return;
    }

    conn->fd = client;
    mgmt_session_init(&conn->session, global_deps);
    mgmt_parser_init(&conn->parser);
    buffer_init(&conn->read_buffer, sizeof(conn->raw_read), conn->raw_read);
    buffer_init(&conn->write_buffer, sizeof(conn->raw_write), conn->raw_write);

    if (selector_register(key->s, client, &mgmt_handler, OP_READ, conn) != SELECTOR_SUCCESS) {
        free(conn);
        close(client);
        return;
    }
    active_mgmt_connections++;
}
