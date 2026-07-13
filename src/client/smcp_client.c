#include "smcp_client.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool
send_all(int fd, const char *s, FILE *err)
{
    size_t off = 0;
    size_t len = strlen(s);
    while (off < len) {
        ssize_t n = send(fd, s + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            fprintf(err, "send: %s\n", strerror(errno));
            return false;
        }
    }
    return true;
}

static bool
read_line(int fd, char *buf, size_t cap, FILE *err)
{
    size_t len = 0;
    while (len + 1 < cap) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n > 0) {
            if (c == '\n') {
                if (len > 0 && buf[len - 1] == '\r') {
                    len--;
                }
                buf[len] = '\0';
                return true;
            }
            buf[len++] = c;
        } else if (n == 0) {
            fprintf(err, "server closed the connection\n");
            return false;
        } else if (errno != EINTR) {
            fprintf(err, "recv: %s\n", strerror(errno));
            return false;
        }
    }
    fprintf(err, "response line too long\n");
    return false;
}

static smcp_result
run_command(int fd, const char *command, const char *display_command, bool verbose, FILE *out, FILE *err)
{
    char wire[SMCP_LINE_MAX];
    int n = snprintf(wire, sizeof(wire), "%s\n", command);
    if (n < 0 || (size_t)n >= sizeof(wire)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    if (!send_all(fd, wire, err)) {
        return SMCP_RESULT_TRANSPORT_ERROR;
    }

    if (verbose) {
        fprintf(out, "\nCommand\n  %s\n\nResponse\n", display_command);
        fflush(out);
    }

    char line[SMCP_LINE_MAX];
    if (!read_line(fd, line, sizeof(line), err)) {
        return SMCP_RESULT_TRANSPORT_ERROR;
    }
    if (strncmp(line, "+OK SMCP ", 9) == 0 &&
        !read_line(fd, line, sizeof(line), err)) {
        return SMCP_RESULT_TRANSPORT_ERROR;
    }

    if (strncmp(line, "-ERR ", 5) == 0) {
        fprintf(err, "%s\n", verbose ? line : line + 5);
        return SMCP_RESULT_REJECTED;
    }
    if (strncmp(line, "+OK", 3) != 0) {
        fprintf(err, "malformed response: %s\n", line);
        return SMCP_RESULT_TRANSPORT_ERROR;
    }

    unsigned long count;
    if (smcp_parse_count_status(line, &count)) {
        if (verbose) {
            fprintf(out, "  %s\n", line);
        }
        for (unsigned long i = 0; i < count; i++) {
            if (!read_line(fd, line, sizeof(line), err)) {
                return SMCP_RESULT_TRANSPORT_ERROR;
            }
            fprintf(out, "%s%s\n", verbose ? "  " : "", line);
        }
    } else if (verbose) {
        fprintf(out, "  %s\n", line);
    } else if (strcmp(line, "+OK") == 0) {
        fprintf(out, "\n");
    } else if (strncmp(line, "+OK ", 4) == 0) {
        fprintf(out, "%s\n", line + 4);
    } else {
        fprintf(out, "%s\n", line);
    }
    fflush(out);
    return SMCP_RESULT_OK;
}

static bool
build_command(char *dst, size_t cap, const char *fmt, const char *a, const char *b)
{
    int n = b == NULL ? snprintf(dst, cap, fmt, a) : snprintf(dst, cap, fmt, a, b);
    return n >= 0 && (size_t)n < cap;
}

int
smcp_connect(const char *host, unsigned short port, FILE *err)
{
    char port_s[6];
    snprintf(port_s, sizeof(port_s), "%hu", port);

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV,
    };

    struct addrinfo *list;
    int gai = getaddrinfo(host, port_s, &hints, &list);
    if (gai != 0) {
        fprintf(err, "getaddrinfo: %s\n", gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = list; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);

    if (fd < 0) {
        fprintf(err, "connect: %s\n", strerror(errno));
    }
    return fd;
}

bool
smcp_is_token(const char *s)
{
    if (s[0] == '\0') {
        return false;
    }
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (isspace(c) || c < 0x21 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

bool
smcp_parse_count_status(const char *line, unsigned long *out)
{
    if (strncmp(line, "+OK ", 4) != 0 || !isdigit((unsigned char)line[4])) {
        return false;
    }

    char *end = NULL;
    errno = 0;
    unsigned long n = strtoul(line + 4, &end, 10);
    if (errno == ERANGE || *end != '\0') {
        return false;
    }
    *out = n;
    return true;
}

smcp_result
smcp_cmd_auth(int fd, const char *user, const char *pass, bool verbose, FILE *out, FILE *err)
{
    char cmd[SMCP_LINE_MAX];
    if (!build_command(cmd, sizeof(cmd), "AUTH %s %s", user, pass)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    return run_command(fd, cmd, "AUTH <admin> <password>", verbose, out, err);
}

smcp_result
smcp_cmd_metrics(int fd, bool verbose, FILE *out, FILE *err)
{
    return run_command(fd, "METRICS", "METRICS", verbose, out, err);
}

smcp_result
smcp_cmd_list_users(int fd, bool verbose, FILE *out, FILE *err)
{
    return run_command(fd, "LIST-USERS", "LIST-USERS", verbose, out, err);
}

smcp_result
smcp_cmd_add_user(int fd, const char *user, const char *pass, bool verbose, FILE *out, FILE *err)
{
    char cmd[SMCP_LINE_MAX];
    char display[SMCP_LINE_MAX];
    if (!build_command(cmd, sizeof(cmd), "ADD-USER %s %s", user, pass)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    if (!build_command(display, sizeof(display), "ADD-USER %s %s", user, "<password>")) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    return run_command(fd, cmd, display, verbose, out, err);
}

smcp_result
smcp_cmd_del_user(int fd, const char *user, bool verbose, FILE *out, FILE *err)
{
    char cmd[SMCP_LINE_MAX];
    if (!build_command(cmd, sizeof(cmd), "DEL-USER %s", user, NULL)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    return run_command(fd, cmd, cmd, verbose, out, err);
}

smcp_result
smcp_cmd_get_config(int fd, bool verbose, FILE *out, FILE *err)
{
    return run_command(fd, "GET-CONFIG", "GET-CONFIG", verbose, out, err);
}

smcp_result
smcp_cmd_set(int fd, const char *key, const char *value, bool verbose, FILE *out, FILE *err)
{
    char cmd[SMCP_LINE_MAX];
    if (!build_command(cmd, sizeof(cmd), "SET %s %s", key, value)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    return run_command(fd, cmd, cmd, verbose, out, err);
}

smcp_result
smcp_cmd_log(int fd, const char *count, bool verbose, FILE *out, FILE *err)
{
    char cmd[SMCP_LINE_MAX];
    if (count == NULL || count[0] == '\0') {
        snprintf(cmd, sizeof(cmd), "LOG");
    } else if (!build_command(cmd, sizeof(cmd), "LOG %s", count, NULL)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    return run_command(fd, cmd, cmd, verbose, out, err);
}

smcp_result
smcp_cmd_passwd(int fd, const char *pass, bool verbose, FILE *out, FILE *err)
{
    char cmd[SMCP_LINE_MAX];
    if (!build_command(cmd, sizeof(cmd), "PASSWD %s", pass, NULL)) {
        fprintf(err, "command too long\n");
        return SMCP_RESULT_REJECTED;
    }
    return run_command(fd, cmd, "PASSWD <new-password>", verbose, out, err);
}

smcp_result
smcp_cmd_help(int fd, bool verbose, FILE *out, FILE *err)
{
    return run_command(fd, "HELP", "HELP", verbose, out, err);
}

smcp_result
smcp_cmd_quit(int fd, bool verbose, FILE *out, FILE *err)
{
    return run_command(fd, "QUIT", "QUIT", verbose, out, err);
}
