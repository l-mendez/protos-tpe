#include "management.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "metrics.h"
#include "runtime_config.h"
#include "runtime_users.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

struct management_conn {
    int fd;
    char line[MANAGEMENT_LINE_MAX + 1];
    size_t line_len;
    char response[MANAGEMENT_RESPONSE_MAX];
    size_t response_len;
    size_t response_sent;
    bool active_counted;
};

static char admin_name[256];
static char admin_pass[256];
static bool admin_configured = false;
static size_t active_connections = 0;

static int would_block(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

static void response_ok(char *out, size_t cap, const char *payload)
{
    if (payload == NULL || payload[0] == '\0') {
        snprintf(out, cap, "OK\n");
    } else {
        snprintf(out, cap, "OK %s\n", payload);
    }
}

static void response_err(char *out, size_t cap, const char *code, const char *message)
{
    snprintf(out, cap, "ERR %s %s\n", code, message);
}

static bool token_valid(const char *s)
{
    size_t len;

    if (s == NULL) {
        return false;
    }
    len = strlen(s);
    if (len == 0 || len > 255) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isspace(c) || c < 0x21 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

void management_set_admin(const char *name, const char *pass)
{
    admin_configured = false;
    admin_name[0] = '\0';
    admin_pass[0] = '\0';
    if (!token_valid(name) || !token_valid(pass)) {
        return;
    }
    snprintf(admin_name, sizeof(admin_name), "%s", name);
    snprintf(admin_pass, sizeof(admin_pass), "%s", pass);
    admin_configured = true;
}

static size_t split_tokens(char *line, char *tokens[], size_t max_tokens)
{
    size_t count = 0;
    char *p = line;

    while (*p != '\0') {
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        if (count == max_tokens) {
            return max_tokens + 1;
        }
        tokens[count++] = p;
        while (*p != '\0' && !isspace((unsigned char)*p)) {
            p++;
        }
        if (*p != '\0') {
            *p++ = '\0';
        }
    }
    return count;
}

static void dispatch_users(size_t ntokens, char *tokens[], char *out, size_t cap)
{
    char payload[MANAGEMENT_RESPONSE_MAX - 4];
    runtime_user_result result;

    if (ntokens < 5) {
        response_err(out, cap, "BAD_REQUEST", "malformed USERS command");
        return;
    }
    if (strcmp(tokens[4], "LIST") == 0 && ntokens == 5) {
        if (!runtime_users_format_list(payload, sizeof(payload))) {
            response_err(out, cap, "INTERNAL", "response too large");
            return;
        }
        response_ok(out, cap, payload);
        return;
    }
    if (strcmp(tokens[4], "ADD") == 0 && ntokens == 7) {
        result = runtime_users_add(tokens[5], tokens[6]);
        if (result == RUNTIME_USER_OK) {
            response_ok(out, cap, "user added");
        } else if (result == RUNTIME_USER_EXISTS) {
            response_err(out, cap, "ALREADY_EXISTS", "user already exists");
        } else if (result == RUNTIME_USER_FULL) {
            response_err(out, cap, "LIMIT_EXCEEDED", "user limit reached");
        } else {
            response_err(out, cap, "INVALID_VALUE", "invalid user or password");
        }
        return;
    }
    if (strcmp(tokens[4], "DEL") == 0 && ntokens == 6) {
        result = runtime_users_del(tokens[5]);
        if (result == RUNTIME_USER_OK) {
            response_ok(out, cap, "user deleted");
        } else if (result == RUNTIME_USER_NOT_FOUND) {
            response_err(out, cap, "NOT_FOUND", "user not found");
        } else {
            response_err(out, cap, "INVALID_VALUE", "invalid user");
        }
        return;
    }
    if (strcmp(tokens[4], "PASSWD") == 0 && ntokens == 7) {
        result = runtime_users_passwd(tokens[5], tokens[6]);
        if (result == RUNTIME_USER_OK) {
            response_ok(out, cap, "password updated");
        } else if (result == RUNTIME_USER_NOT_FOUND) {
            response_err(out, cap, "NOT_FOUND", "user not found");
        } else {
            response_err(out, cap, "INVALID_VALUE", "invalid user or password");
        }
        return;
    }
    response_err(out, cap, "BAD_REQUEST", "malformed USERS command");
}

static void dispatch_config(size_t ntokens, char *tokens[], char *out, size_t cap)
{
    char payload[MANAGEMENT_RESPONSE_MAX - 4];
    runtime_config_result result;

    if (ntokens < 5) {
        response_err(out, cap, "BAD_REQUEST", "malformed CONFIG command");
        return;
    }
    if (strcmp(tokens[4], "LIST") == 0 && ntokens == 5) {
        if (!runtime_config_format_list(payload, sizeof(payload))) {
            response_err(out, cap, "INTERNAL", "response too large");
            return;
        }
        response_ok(out, cap, payload);
        return;
    }
    if (strcmp(tokens[4], "GET") == 0 && ntokens == 6) {
        if (!runtime_config_get(tokens[5], payload, sizeof(payload))) {
            response_err(out, cap, "NOT_FOUND", "config key not found");
            return;
        }
        response_ok(out, cap, payload);
        return;
    }
    if (strcmp(tokens[4], "SET") == 0 && ntokens == 7) {
        result = runtime_config_set(tokens[5], tokens[6]);
        if (result == RUNTIME_CONFIG_OK) {
            response_ok(out, cap, "config updated");
        } else if (result == RUNTIME_CONFIG_NOT_FOUND) {
            response_err(out, cap, "NOT_FOUND", "config key not found");
        } else {
            response_err(out, cap, "INVALID_VALUE", "invalid config value");
        }
        return;
    }
    response_err(out, cap, "BAD_REQUEST", "malformed CONFIG command");
}

void management_dispatch_line(const char *line, char *out, size_t cap)
{
    char copy[MANAGEMENT_LINE_MAX + 1];
    char *tokens[8];
    size_t len;
    size_t ntokens;
    char payload[MANAGEMENT_RESPONSE_MAX - 4];

    if (out == NULL || cap == 0) {
        return;
    }
    out[0] = '\0';
    if (line == NULL) {
        response_err(out, cap, "BAD_REQUEST", "empty request");
        return;
    }
    len = strcspn(line, "\n");
    if (len > 0 && line[len - 1] == '\r') {
        len--;
    }
    if (len > MANAGEMENT_LINE_MAX) {
        response_err(out, cap, "LIMIT_EXCEEDED", "request line too long");
        return;
    }
    memcpy(copy, line, len);
    copy[len] = '\0';

    ntokens = split_tokens(copy, tokens, sizeof(tokens) / sizeof(tokens[0]));
    if (ntokens > sizeof(tokens) / sizeof(tokens[0])) {
        response_err(out, cap, "BAD_REQUEST", "too many arguments");
        return;
    }
    if (ntokens < 4 || strcmp(tokens[0], "AUTH") != 0) {
        response_err(out, cap, "BAD_REQUEST", "expected AUTH user pass command");
        return;
    }
    if (!admin_configured || strcmp(tokens[1], admin_name) != 0 ||
        strcmp(tokens[2], admin_pass) != 0) {
        response_err(out, cap, "UNAUTHORIZED", "invalid credentials");
        return;
    }
    if (strcmp(tokens[3], "METRICS") == 0 && ntokens == 4) {
        if (!metrics_format(payload, sizeof(payload))) {
            response_err(out, cap, "INTERNAL", "response too large");
            return;
        }
        response_ok(out, cap, payload);
        return;
    }
    if (strcmp(tokens[3], "USERS") == 0) {
        dispatch_users(ntokens, tokens, out, cap);
        return;
    }
    if (strcmp(tokens[3], "CONFIG") == 0) {
        dispatch_config(ntokens, tokens, out, cap);
        return;
    }
    response_err(out, cap, "UNKNOWN_COMMAND", "unknown command");
}

static void prepare_response(struct management_conn *c, const char *response)
{
    snprintf(c->response, sizeof(c->response), "%s", response);
    c->response_len = strlen(c->response);
    c->response_sent = 0;
}

static void management_close(struct selector_key *key)
{
    struct management_conn *c = key->data;

    close(key->fd);
    if (c != NULL) {
        if (c->active_counted && active_connections > 0) {
            active_connections--;
        }
        free(c);
    }
}

static void management_read(struct selector_key *key)
{
    struct management_conn *c = key->data;
    char buf[256];
    ssize_t n = recv(key->fd, buf, sizeof(buf), 0);

    if (n < 0 && would_block(errno)) {
        return;
    }
    if (n <= 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\n') {
            c->line[c->line_len] = '\0';
            management_dispatch_line(c->line, c->response, sizeof(c->response));
            c->response_len = strlen(c->response);
            c->response_sent = 0;
            (void)selector_set_interest_key(key, OP_WRITE);
            return;
        }
        if (c->line_len >= MANAGEMENT_LINE_MAX) {
            prepare_response(c, "ERR LIMIT_EXCEEDED request line too long\n");
            (void)selector_set_interest_key(key, OP_WRITE);
            return;
        }
        c->line[c->line_len++] = buf[i];
    }
}

static void management_write(struct selector_key *key)
{
    struct management_conn *c = key->data;
    size_t pending = c->response_len - c->response_sent;
    ssize_t n;

    if (pending == 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }
    n = send(key->fd, c->response + c->response_sent, pending, MSG_NOSIGNAL);
    if (n < 0 && would_block(errno)) {
        return;
    }
    if (n <= 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }
    c->response_sent += (size_t)n;
    if (c->response_sent == c->response_len) {
        selector_unregister_fd(key->s, key->fd);
    }
}

static const fd_handler management_handler = {
    .handle_read = management_read,
    .handle_write = management_write,
    .handle_close = management_close,
};

void management_passive_accept(struct selector_key *key)
{
    int client = accept(key->fd, NULL, NULL);
    struct management_conn *conn;

    if (client < 0) {
        return;
    }
    if (selector_fd_set_nio(client) < 0) {
        close(client);
        return;
    }
    conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
        close(client);
        return;
    }
    conn->fd = client;
    conn->active_counted = true;
    if (selector_register(key->s, client, &management_handler, OP_READ, conn) != SELECTOR_SUCCESS) {
        free(conn);
        close(client);
        return;
    }
    active_connections++;
}

size_t management_active_connections(void)
{
    return active_connections;
}
