#include "loadgen.h"

#include "stress_config.h"
#include "stress_helpers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum conn_state {
    CONN_CONNECTING,
    CONN_SEND_NEGOTIATION,
    CONN_RECV_NEGOTIATION,
    CONN_SEND_AUTH,
    CONN_RECV_AUTH,
    CONN_SEND_CONNECT,
    CONN_RECV_CONNECT,
    CONN_READY,
    CONN_SEND_PAYLOAD,
    CONN_RECV_PAYLOAD,
    CONN_WAIT,
    CONN_HOLD,
    CONN_DONE,
    CONN_FAILED,
};

struct load_conn {
    int fd;
    enum conn_state state;
    size_t id;
    uint8_t control[520];
    size_t tx_len;
    size_t tx_off;
    size_t rx_goal;
    size_t rx_off;
    uint8_t payload[STRESS_CHUNK_SIZE];
    size_t chunk;
    size_t payload_off;
    uint64_t goal;
    uint64_t completed;
    double next_send;
    bool counted_failed;
};

static double monotonic_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static bool write_full(int fd, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static void emit_event(const struct stress_load_config *cfg, uint32_t type,
                       size_t connected, size_t failed, size_t corrupted,
                       uint64_t bytes, double seconds)
{
    struct stress_load_event event = {
        .type = type,
        .requested = (uint32_t)cfg->concurrency,
        .connected = (uint32_t)connected,
        .failed = (uint32_t)failed,
        .corrupted = (uint32_t)corrupted,
        .bytes = bytes,
        .seconds = seconds,
    };
    (void)write_full(cfg->event_fd, &event, sizeof(event));
}

static void fail_conn(struct load_conn *c, size_t *failed)
{
    if (!c->counted_failed) {
        c->counted_failed = true;
        (*failed)++;
    }
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->state = CONN_FAILED;
}

static void close_done(struct load_conn *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->state = CONN_DONE;
}

static void prepare_control(struct load_conn *c, enum conn_state state, int len)
{
    c->state = state;
    c->tx_len = (size_t)len;
    c->tx_off = 0;
    c->rx_off = 0;
}

static uint8_t pattern_byte(size_t id, uint64_t offset)
{
    return (uint8_t)((id * 31u + offset) & 0xffu);
}

static void prepare_payload(struct load_conn *c, size_t size)
{
    c->chunk = size;
    c->payload_off = 0;
    for (size_t i = 0; i < size; i++) {
        c->payload[i] = pattern_byte(c->id, c->completed + i);
    }
    c->state = CONN_SEND_PAYLOAD;
}

static bool begin_connection(struct load_conn *c, uint16_t proxy_port)
{
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0 || set_nonblocking(c->fd) < 0) {
        if (c->fd >= 0) close(c->fd);
        c->fd = -1;
        return false;
    }
    struct sockaddr_in proxy = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(proxy_port),
    };
    int rc = connect(c->fd, (struct sockaddr *)&proxy, sizeof(proxy));
    if (rc == 0) {
        int len = stress_build_negotiation(c->control, sizeof(c->control));
        prepare_control(c, CONN_SEND_NEGOTIATION, len);
    } else if (errno == EINPROGRESS) {
        c->state = CONN_CONNECTING;
    } else {
        close(c->fd);
        c->fd = -1;
        return false;
    }
    return true;
}

static short interest(const struct load_conn *c)
{
    switch (c->state) {
        case CONN_CONNECTING:
        case CONN_SEND_NEGOTIATION:
        case CONN_SEND_AUTH:
        case CONN_SEND_CONNECT:
        case CONN_SEND_PAYLOAD:
            return POLLOUT;
        case CONN_RECV_NEGOTIATION:
        case CONN_RECV_AUTH:
        case CONN_RECV_CONNECT:
        case CONN_RECV_PAYLOAD:
            return POLLIN;
        default:
            return 0;
    }
}

static void finish_control_send(struct load_conn *c)
{
    c->rx_off = 0;
    if (c->state == CONN_SEND_NEGOTIATION) {
        c->state = CONN_RECV_NEGOTIATION;
        c->rx_goal = 2;
    } else if (c->state == CONN_SEND_AUTH) {
        c->state = CONN_RECV_AUTH;
        c->rx_goal = 2;
    } else {
        c->state = CONN_RECV_CONNECT;
        c->rx_goal = 10;
    }
}

static bool handle_control_read(struct load_conn *c, uint16_t target_port)
{
    if (c->rx_off < c->rx_goal) return true;
    if (c->state == CONN_RECV_NEGOTIATION) {
        if (!stress_validate_negotiation(c->control)) return false;
        int len = stress_build_auth(c->control, sizeof(c->control),
                                    STRESS_PROXY_USER, STRESS_PROXY_PASS);
        prepare_control(c, CONN_SEND_AUTH, len);
    } else if (c->state == CONN_RECV_AUTH) {
        if (!stress_validate_auth(c->control)) return false;
        int len = stress_build_connect_ipv4(c->control, sizeof(c->control),
                                            0x7f000001u, target_port);
        prepare_control(c, CONN_SEND_CONNECT, len);
    } else {
        if (!stress_validate_connect_ipv4(c->control)) return false;
        c->state = CONN_READY;
    }
    return true;
}

static void start_workload(const struct stress_load_config *cfg,
                           struct load_conn *conns, double now)
{
    uint64_t base = cfg->mode == STRESS_LOAD_THROUGHPUT
                        ? cfg->total_bytes / cfg->concurrency
                        : STRESS_CAPACITY_PAYLOAD;
    uint64_t remainder = cfg->mode == STRESS_LOAD_THROUGHPUT
                             ? cfg->total_bytes % cfg->concurrency
                             : 0;
    for (size_t i = 0; i < cfg->concurrency; i++) {
        conns[i].goal = cfg->mode == STRESS_LOAD_SOAK ? UINT64_MAX
                                                       : base + (i < remainder);
        conns[i].completed = 0;
        conns[i].next_send = now;
        size_t chunk = cfg->mode == STRESS_LOAD_SOAK
                           ? STRESS_SOAK_PAYLOAD
                           : (size_t)(conns[i].goal < STRESS_CHUNK_SIZE
                                          ? conns[i].goal
                                          : STRESS_CHUNK_SIZE);
        prepare_payload(&conns[i], chunk);
    }
}

static void advance_after_payload(const struct stress_load_config *cfg,
                                  struct load_conn *c, double now,
                                  size_t *finished)
{
    c->completed += c->chunk;
    if (cfg->mode == STRESS_LOAD_SOAK) {
        c->state = CONN_WAIT;
        c->next_send = now + 1.0;
    } else if (c->completed >= c->goal) {
        if (cfg->mode == STRESS_LOAD_CAPACITY) {
            c->state = CONN_HOLD;
        } else {
            close_done(c);
        }
        (*finished)++;
    } else {
        uint64_t remaining = c->goal - c->completed;
        prepare_payload(c, (size_t)(remaining < STRESS_CHUNK_SIZE
                                        ? remaining
                                        : STRESS_CHUNK_SIZE));
    }
}

int stress_load_run(const struct stress_load_config *cfg)
{
    if (cfg == NULL || cfg->concurrency == 0 ||
        cfg->concurrency > STRESS_CEILING_CONNECTIONS) {
        return 2;
    }
    struct load_conn *conns = calloc(cfg->concurrency, sizeof(*conns));
    struct pollfd *pfds = calloc(cfg->concurrency, sizeof(*pfds));
    if (conns == NULL || pfds == NULL) {
        free(conns);
        free(pfds);
        return 2;
    }

    size_t failed = 0, corrupted = 0, ready = 0, connected = 0, finished = 0;
    for (size_t i = 0; i < cfg->concurrency; i++) {
        conns[i].id = i;
        conns[i].fd = -1;
        if (!begin_connection(&conns[i], cfg->proxy_port)) {
            fail_conn(&conns[i], &failed);
        }
    }

    double setup_start = monotonic_seconds();
    double work_start = 0.0;
    bool workload_started = false;
    bool ready_emitted = false;
    uint64_t total_bytes = 0;

    for (;;) {
        double now = monotonic_seconds();
        if (workload_started && failed > 0) {
            break;
        }
        if (!workload_started && now - setup_start > STRESS_HANDSHAKE_TIMEOUT_SECONDS) {
            for (size_t i = 0; i < cfg->concurrency; i++) {
                if (conns[i].state != CONN_READY && conns[i].state != CONN_FAILED)
                    fail_conn(&conns[i], &failed);
            }
        }

        ready = 0;
        for (size_t i = 0; i < cfg->concurrency; i++) {
            if (conns[i].state == CONN_READY) ready++;
        }
        if (!workload_started && ready + failed == cfg->concurrency) {
            if (failed > 0) break;
            connected = ready;
            workload_started = true;
            work_start = now;
            start_workload(cfg, conns, now);
            if (cfg->mode != STRESS_LOAD_CAPACITY) {
                emit_event(cfg, STRESS_LOAD_READY, connected, failed, corrupted, 0, 0.0);
                ready_emitted = true;
            }
        }

        if (workload_started && cfg->mode == STRESS_LOAD_SOAK &&
            now - work_start >= cfg->duration_seconds) {
            for (size_t i = 0; i < cfg->concurrency; i++) {
                if (conns[i].state == CONN_WAIT) {
                    close_done(&conns[i]);
                    finished++;
                }
            }
        }

        if (workload_started && finished == cfg->concurrency) {
            if (cfg->mode == STRESS_LOAD_CAPACITY) {
                emit_event(cfg, STRESS_LOAD_READY, cfg->concurrency, failed,
                           corrupted, total_bytes, now - work_start);
                ready_emitted = true;
                struct pollfd control = {.fd = cfg->control_fd, .events = POLLIN};
                if (poll(&control, 1, (int)((STRESS_CAPACITY_HOLD_SECONDS + 30u) * 1000u)) <= 0) {
                    failed++;
                } else {
                    char release;
                    if (read(cfg->control_fd, &release, 1) != 1) failed++;
                }
                for (size_t i = 0; i < cfg->concurrency; i++) close_done(&conns[i]);
            }
            break;
        }

        if (workload_started && now - work_start > STRESS_RUN_TIMEOUT_SECONDS +
                (cfg->mode == STRESS_LOAD_SOAK ? cfg->duration_seconds : 0u)) {
            failed++;
            break;
        }

        for (size_t i = 0; i < cfg->concurrency; i++) {
            if (cfg->mode == STRESS_LOAD_SOAK && conns[i].state == CONN_WAIT &&
                now - work_start < cfg->duration_seconds && now >= conns[i].next_send) {
                prepare_payload(&conns[i], STRESS_SOAK_PAYLOAD);
            }
            pfds[i].fd = conns[i].fd;
            pfds[i].events = interest(&conns[i]);
            pfds[i].revents = 0;
        }
        int polled = poll(pfds, cfg->concurrency, STRESS_POLL_INTERVAL_MS);
        if (polled < 0) {
            if (errno == EINTR) continue;
            failed++;
            break;
        }

        for (size_t i = 0; i < cfg->concurrency; i++) {
            struct load_conn *c = &conns[i];
            short events = pfds[i].revents;
            if (c->fd < 0 || events == 0) continue;
            if (c->state == CONN_CONNECTING &&
                (events & (POLLOUT | POLLERR | POLLHUP)) != 0) {
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                    fail_conn(c, &failed);
                    continue;
                }
                int n = stress_build_negotiation(c->control, sizeof(c->control));
                prepare_control(c, CONN_SEND_NEGOTIATION, n);
                events |= POLLOUT;
            }
            if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
                c->state != CONN_CONNECTING) {
                fail_conn(c, &failed);
                continue;
            }
            if ((events & POLLOUT) != 0) {
                if (c->state == CONN_SEND_PAYLOAD) {
                    ssize_t n = send(c->fd, c->payload + c->payload_off,
                                     c->chunk - c->payload_off, 0);
                    if (n > 0) {
                        c->payload_off += (size_t)n;
                        if (c->payload_off == c->chunk) {
                            c->payload_off = 0;
                            c->state = CONN_RECV_PAYLOAD;
                        }
                    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        fail_conn(c, &failed);
                    }
                } else if (c->state == CONN_SEND_NEGOTIATION ||
                           c->state == CONN_SEND_AUTH || c->state == CONN_SEND_CONNECT) {
                    ssize_t n = send(c->fd, c->control + c->tx_off,
                                     c->tx_len - c->tx_off, 0);
                    if (n > 0) {
                        c->tx_off += (size_t)n;
                        if (c->tx_off == c->tx_len) finish_control_send(c);
                    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        fail_conn(c, &failed);
                    }
                }
            }
            if (c->fd >= 0 && (events & POLLIN) != 0) {
                if (c->state == CONN_RECV_PAYLOAD) {
                    uint8_t incoming[STRESS_CHUNK_SIZE];
                    size_t remaining = c->chunk - c->payload_off;
                    ssize_t n = recv(c->fd, incoming, remaining, 0);
                    if (n > 0) {
                        for (ssize_t j = 0; j < n; j++) {
                            uint64_t offset = c->completed + c->payload_off + (size_t)j;
                            if (incoming[j] != pattern_byte(c->id, offset)) {
                                corrupted++;
                                fail_conn(c, &failed);
                                break;
                            }
                        }
                        if (c->state != CONN_FAILED) {
                            c->payload_off += (size_t)n;
                            if (c->payload_off == c->chunk) {
                                total_bytes += c->chunk;
                                c->payload_off = 0;
                                advance_after_payload(cfg, c, now, &finished);
                            }
                        }
                    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                        fail_conn(c, &failed);
                    }
                } else if (c->state == CONN_RECV_NEGOTIATION ||
                           c->state == CONN_RECV_AUTH || c->state == CONN_RECV_CONNECT) {
                    ssize_t n = recv(c->fd, c->control + c->rx_off,
                                     c->rx_goal - c->rx_off, 0);
                    if (n > 0) {
                        c->rx_off += (size_t)n;
                        if (!handle_control_read(c, cfg->target_port)) fail_conn(c, &failed);
                    } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                        fail_conn(c, &failed);
                    }
                }
            }
        }
    }

    double seconds = workload_started ? monotonic_seconds() - work_start : 0.0;
    for (size_t i = 0; i < cfg->concurrency; i++) {
        if (conns[i].fd >= 0) close(conns[i].fd);
    }
    if (!ready_emitted && cfg->mode != STRESS_LOAD_THROUGHPUT)
        emit_event(cfg, STRESS_LOAD_READY, ready, failed, corrupted, total_bytes, seconds);
    emit_event(cfg, STRESS_LOAD_DONE, connected, failed, corrupted, total_bytes, seconds);
    free(conns);
    free(pfds);
    return failed == 0 && corrupted == 0 ? 0 : 1;
}
