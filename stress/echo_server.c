#include "echo_server.h"

#include "stress_config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct echo_conn {
    uint8_t data[STRESS_CHUNK_SIZE];
    size_t len;
    size_t off;
};

static volatile sig_atomic_t echo_stop = 0;

static void echo_signal(int signal)
{
    (void)signal;
    echo_stop = 1;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int stress_echo_create(uint16_t *port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, SOMAXCONN) < 0 || set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(addr.sin_port);
    return fd;
}

static void close_slot(struct pollfd *pfd, struct echo_conn *conn)
{
    close(pfd->fd);
    pfd->fd = -1;
    pfd->events = 0;
    conn->len = 0;
    conn->off = 0;
}

int stress_echo_run(int listener_fd)
{
    const size_t slots = STRESS_CEILING_CONNECTIONS + 65u;
    struct pollfd *pfds = calloc(slots, sizeof(*pfds));
    struct echo_conn *conns = calloc(slots, sizeof(*conns));
    if (pfds == NULL || conns == NULL) {
        free(pfds);
        free(conns);
        return 1;
    }
    for (size_t i = 0; i < slots; i++) {
        pfds[i].fd = -1;
    }
    pfds[0].fd = listener_fd;
    pfds[0].events = POLLIN;

    struct sigaction action = {.sa_handler = echo_signal};
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    while (!echo_stop) {
        int ready = poll(pfds, slots, STRESS_POLL_INTERVAL_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if ((pfds[0].revents & POLLIN) != 0) {
            for (;;) {
                int client = accept(listener_fd, NULL, NULL);
                if (client < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                    echo_stop = 1;
                    break;
                }
                if (set_nonblocking(client) < 0) {
                    close(client);
                    continue;
                }
                size_t slot;
                for (slot = 1; slot < slots && pfds[slot].fd >= 0; slot++) {}
                if (slot == slots) {
                    close(client);
                } else {
                    pfds[slot].fd = client;
                    pfds[slot].events = POLLIN;
                }
            }
        }
        for (size_t i = 1; i < slots; i++) {
            if (pfds[i].fd < 0 || pfds[i].revents == 0) continue;
            if ((pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                close_slot(&pfds[i], &conns[i]);
                continue;
            }
            if (conns[i].len == conns[i].off && (pfds[i].revents & POLLIN) != 0) {
                ssize_t n = recv(pfds[i].fd, conns[i].data, sizeof(conns[i].data), 0);
                if (n > 0) {
                    conns[i].len = (size_t)n;
                    conns[i].off = 0;
                    pfds[i].events = POLLOUT;
                } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    close_slot(&pfds[i], &conns[i]);
                }
            }
            if (pfds[i].fd >= 0 && conns[i].off < conns[i].len &&
                (pfds[i].revents & POLLOUT) != 0) {
                ssize_t n = send(pfds[i].fd, conns[i].data + conns[i].off,
                                 conns[i].len - conns[i].off, 0);
                if (n > 0) {
                    conns[i].off += (size_t)n;
                    if (conns[i].off == conns[i].len) {
                        conns[i].off = conns[i].len = 0;
                        pfds[i].events = POLLIN;
                    }
                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    close_slot(&pfds[i], &conns[i]);
                }
            }
        }
    }
    for (size_t i = 0; i < slots; i++) {
        if (pfds[i].fd >= 0) close(pfds[i].fd);
    }
    free(pfds);
    free(conns);
    return 0;
}
