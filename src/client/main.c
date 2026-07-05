#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "client_protocol.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define CLIENT_REQUEST_MAX 2048
#define CLIENT_RESPONSE_MAX 4096

static unsigned short port(const char *s)
{
    char *end = NULL;
    const long sl = strtol(s, &end, 10);

    if (end == s || *end != '\0' ||
        ((sl == LONG_MIN || sl == LONG_MAX) && errno == ERANGE) ||
        sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
    }
    return (unsigned short)sl;
}

static void version(void)
{
    fprintf(stderr, "socks5 management client version 0.0\n");
}

static void usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s -a <admin>:<pass> [OPTION]... <command>\n"
            "\n"
            "Options:\n"
            "   -a <admin>:<pass> Credenciales de management.\n"
            "   -L <addr>         Dirección del servicio de management (default 127.0.0.1).\n"
            "   -P <port>         Puerto del servicio de management (default 8080).\n"
            "   -h                Imprime la ayuda y termina.\n"
            "   -v                Imprime la versión y termina.\n"
            "\n"
            "Commands:\n"
            "   metrics\n"
            "   users list\n"
            "   users add <username> <password>\n"
            "   users del <username>\n"
            "   users passwd <username> <password>\n"
            "   config list\n"
            "   config get <key>\n"
            "   config set <key> <value>\n",
            progname);
}

static int split_auth(char *raw, char **user, char **pass)
{
    char *sep = strchr(raw, ':');

    if (sep == NULL || sep == raw || sep[1] == '\0') {
        return -1;
    }
    *sep = '\0';
    *user = raw;
    *pass = sep + 1;
    return 0;
}

static int connect_to_management(const char *addr, unsigned short port_value)
{
    char port_str[6];
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV,
    };
    struct addrinfo *list = NULL;
    int fd = -1;

    snprintf(port_str, sizeof(port_str), "%hu", port_value);
    if (getaddrinfo(addr, port_str, &hints, &list) != 0) {
        return -1;
    }
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
    return fd;
}

static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int read_line(int fd, char *buf, size_t cap)
{
    size_t used = 0;

    if (cap == 0) {
        return -1;
    }
    while (used + 1 < cap) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        buf[used++] = c;
        if (c == '\n') {
            buf[used] = '\0';
            return 0;
        }
    }
    buf[0] = '\0';
    return -1;
}

int main(const int argc, char **argv)
{
    const char *addr = "127.0.0.1";
    unsigned short mng_port = 8080;
    char *auth = NULL;
    char *admin = NULL;
    char *pass = NULL;
    char command[CLIENT_REQUEST_MAX];
    char request[CLIENT_REQUEST_MAX];
    char response[CLIENT_RESPONSE_MAX];
    int c;
    int fd;
    int written;

    while ((c = getopt(argc, argv, "a:hL:P:v")) != -1) {
        switch (c) {
        case 'a':
            auth = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'L':
            addr = optarg;
            break;
        case 'P':
            mng_port = port(optarg);
            break;
        case 'v':
            version();
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (auth == NULL || split_auth(auth, &admin, &pass) < 0) {
        fprintf(stderr, "invalid or missing management credentials (-a admin:pass)\n");
        return 1;
    }
    if (client_build_command(argc - optind, argv + optind,
                             command, sizeof(command)) != CLIENT_CMD_OK) {
        usage(argv[0]);
        return 1;
    }
    written = snprintf(request, sizeof(request), "AUTH %s %s %s\n",
                       admin, pass, command);
    if (written < 0 || (size_t)written >= sizeof(request)) {
        fprintf(stderr, "request too long\n");
        return 1;
    }

    fd = connect_to_management(addr, mng_port);
    if (fd < 0) {
        fprintf(stderr, "could not connect to management server %s:%hu\n",
                addr, mng_port);
        return 1;
    }
    if (send_all(fd, request, (size_t)written) < 0 ||
        read_line(fd, response, sizeof(response)) < 0) {
        fprintf(stderr, "management protocol I/O failed\n");
        close(fd);
        return 1;
    }
    close(fd);

    if (strcmp(response, "OK\n") == 0) {
        fputs("OK\n", stdout);
        return 0;
    }
    if (strncmp(response, "OK ", 3) == 0) {
        fputs(response + 3, stdout);
        return 0;
    }
    if (strncmp(response, "ERR ", 4) == 0) {
        fputs(response, stderr);
        return 1;
    }
    fprintf(stderr, "invalid management response: %s", response);
    return 1;
}
