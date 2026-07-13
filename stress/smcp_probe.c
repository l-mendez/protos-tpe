#include "smcp_probe.h"

#include "stress_config.h"
#include "stress_helpers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static bool send_all(int fd, const char *text)
{
    return stress_write_full(fd, text, strlen(text));
}

struct line_reader {
    int fd;
    char buf[512];
    size_t pos;   /* next unread byte in buf */
    size_t len;   /* bytes currently in buf */
};

static bool read_line(struct line_reader *r, char *dst, size_t cap)
{
    if (cap < 2) return false;
    size_t used = 0;
    while (used + 1 < cap) {
        if (r->pos == r->len) {
            ssize_t n = recv(r->fd, r->buf, sizeof(r->buf), 0);
            if (n > 0) {
                r->pos = 0;
                r->len = (size_t)n;
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                return false;
            }
        }
        char c = r->buf[r->pos++];
        dst[used++] = c;
        if (c == '\n') {
            dst[used] = '\0';
            return true;
        }
    }
    return false;
}

bool stress_smcp_query_metrics(uint16_t port, struct stress_metrics *metrics)
{
    if (metrics == NULL) return false;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port),
    };
    bool ok = connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0;
    struct line_reader reader = {.fd = fd, .pos = 0, .len = 0};
    char line[256];
    char response[2048] = {0};
    char command[600];
    int command_len = snprintf(command, sizeof(command), "AUTH %s %s\n",
                               STRESS_ADMIN_USER, STRESS_ADMIN_PASS);
    if (ok) ok = command_len > 0 && (size_t)command_len < sizeof(command) &&
                 send_all(fd, command);
    if (ok) ok = read_line(&reader, line, sizeof(line)) &&
                 strcmp(line, "+OK authenticated\n") == 0;
    if (ok) ok = send_all(fd, "METRICS\n") &&
                 read_line(&reader, line, sizeof(line)) &&
                 strcmp(line, "+OK 7\n") == 0;
    if (ok) memcpy(response, line, strlen(line) + 1);
    for (unsigned i = 0; ok && i < 7; i++) {
        ok = read_line(&reader, line, sizeof(line));
        size_t used = strlen(response), len = strlen(line);
        if (ok && used + len < sizeof(response)) {
            memcpy(response + used, line, len + 1);
        } else {
            ok = false;
        }
    }
    if (ok) ok = stress_parse_metrics(response, metrics);
    if (ok) (void)send_all(fd, "QUIT\n");
    close(fd);
    return ok;
}
