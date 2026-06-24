#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <check.h>

#include "selector.h"

/* SOCKS5 units live in src/server, outside the shared archive; include them
 * directly. socks5.c only #includes the parser headers, so pull the parser
 * units in too (each .c exactly once to avoid duplicate symbols). */
#include "../src/server/server.c"
#include "../src/server/negotiation.c"
#include "../src/server/request.c"
#include "../src/server/auth.c"
#include "../src/server/socks5.c"

static fd_selector           test_selector;
static volatile sig_atomic_t test_stop;

/* No users configured: the default policy for the no-auth tests. */
static const struct socks5args no_users = { 0 };

static void *run_selector(void *unused)
{
    (void)unused;
    while (!test_stop) {
        selector_select(test_selector);
    }
    return NULL;
}

/* Yield long enough for the selector thread to advance a few cycles. */
static void sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int connect_to(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ck_assert_int_eq(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    /* keep a stuck read from hanging the suite */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* read exactly n bytes (or fail) */
static void read_exactly(int fd, uint8_t *out, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        ck_assert_int_gt(r, 0);
        got += (size_t)r;
    }
}

static unsigned short start_server(int *passive_out)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 50000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    test_selector = selector_new(64);
    ck_assert_ptr_nonnull(test_selector);

    int passive = server_setup_passive("127.0.0.1", 0);
    ck_assert_int_ge(passive, 0);
    struct sockaddr_in bound;
    socklen_t          bound_len = sizeof(bound);
    ck_assert_int_eq(getsockname(passive, (struct sockaddr *)&bound, &bound_len), 0);

    ck_assert_int_ge(selector_fd_set_nio(passive), 0);
    static const fd_handler passive_handler = { .handle_read = socks5_passive_accept };
    ck_assert_int_eq(
        selector_register(test_selector, passive, &passive_handler, OP_READ, NULL),
        SELECTOR_SUCCESS);

    *passive_out = passive;
    return ntohs(bound.sin_port);
}

static struct socks5_conn *new_registered_test_conn(fd_selector s,
                                                    int client_fd)
{
    struct socks5_conn *c = calloc(1, sizeof(*c));
    ck_assert_ptr_nonnull(c);

    c->selector   = s;
    c->client_fd  = client_fd;
    c->origin_fd  = -1;
    c->references = 1;
    c->stm.initial   = NEG_READ;
    c->stm.states    = socks5_states;
    c->stm.max_state = ERROR;
    stm_init(&c->stm);
    buffer_init(&c->read_buffer, sizeof(c->raw_read), c->raw_read);
    buffer_init(&c->write_buffer, sizeof(c->raw_write), c->raw_write);

    ck_assert_int_eq(selector_register(s, client_fd, &socks5_handler, OP_NOOP, c),
                     SELECTOR_SUCCESS);
    conn_list_push(c);
    active_connections++;
    return c;
}

/* --------------------------------------------------------- origin helpers */

/* A tiny echo server: accepts one connection, echoes everything it receives,
 * and closes when the peer does.  Runs on a dedicated thread. */
struct origin_ctx {
    int            listen_fd;
    unsigned short port;
};

static struct origin_ctx start_origin(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ck_assert_int_eq(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(listen(fd, 1), 0);
    socklen_t len = sizeof(addr);
    ck_assert_int_eq(getsockname(fd, (struct sockaddr *)&addr, &len), 0);
    return (struct origin_ctx){ .listen_fd = fd, .port = ntohs(addr.sin_port) };
}

static void *origin_echo_run(void *arg)
{
    struct origin_ctx *ctx = arg;
    int peer = accept(ctx->listen_fd, NULL, NULL);
    if (peer < 0) {
        return NULL;
    }
    uint8_t buf[512];
    ssize_t n;
    while ((n = read(peer, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(peer, buf + written, (size_t)(n - written));
            if (w <= 0) break;
            written += w;
        }
    }
    close(peer);
    return NULL;
}

/* Encodes the origin port in network byte order into two bytes in the request. */
static void encode_port(uint8_t out[2], unsigned short port)
{
    out[0] = (uint8_t)(port >> 8);
    out[1] = (uint8_t)(port & 0xFF);
}

/* --------------------------------------------------------- test helpers */

/* Perform a no-auth SOCKS5 negotiation on `client` and return. */
static void negotiate_noauth(int client)
{
    uint8_t neg[] = { 0x05, 0x01, 0x00 };
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));
    uint8_t reply[2];
    read_exactly(client, reply, sizeof(reply));
    ck_assert_uint_eq(0x05, reply[0]);
    ck_assert_uint_eq(0x00, reply[1]);
}

/* Send an IPv4 CONNECT request for 127.0.0.1:<port>. */
static void send_connect_ipv4(int client, unsigned short port)
{
    uint8_t req[] = { 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00 };
    encode_port(&req[8], port);
    ck_assert_int_eq(write(client, req, sizeof(req)), (ssize_t)sizeof(req));
}

/* Read the SOCKS5 reply (10 bytes) and return the REP field. */
static uint8_t read_socks5_reply(int client)
{
    uint8_t rep[10];
    read_exactly(client, rep, sizeof(rep));
    ck_assert_uint_eq(0x05, rep[0]);
    return rep[1];
}

/* ======================================================== tests ========= */

/* Negotiation + CONNECT to a live echo origin: full handshake succeeds. */
START_TEST(test_socks5_negotiation_then_connect)
{
    socks5_set_users(&no_users);

    struct origin_ctx origin = start_origin();
    pthread_t origin_tid;
    ck_assert_int_eq(pthread_create(&origin_tid, NULL, origin_echo_run, &origin), 0);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);
    negotiate_noauth(client);
    send_connect_ipv4(client, origin.port);
    ck_assert_uint_eq(SOCKS5_REP_SUCCESS, read_socks5_reply(client));

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    pthread_join(origin_tid, NULL);
    close(origin.listen_fd);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* A bad version in the negotiation must drop the connection (EOF) rather than
 * reply. */
START_TEST(test_socks5_bad_version_closes)
{
    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    uint8_t bad[] = { 0x04, 0x01, 0x00 };
    ck_assert_int_eq(write(client, bad, sizeof(bad)), (ssize_t)sizeof(bad));

    uint8_t scratch[8];
    ssize_t r = read(client, scratch, sizeof(scratch));
    ck_assert_int_eq(r, 0); /* closed without a reply */

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* With users configured, a client that authenticates with valid credentials
 * gets AUTH status 0x00 and a CONNECT to a live origin succeeds. */
START_TEST(test_socks5_userpass_valid_advances)
{
    static const struct socks5args args = { .users = { { .name = "alice", .pass = "secret" } } };
    socks5_set_users(&args);

    struct origin_ctx origin = start_origin();
    pthread_t origin_tid;
    ck_assert_int_eq(pthread_create(&origin_tid, NULL, origin_echo_run, &origin), 0);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    /* negotiation offering user/pass (0x02); auth is required -> server picks it */
    uint8_t neg[] = { 0x05, 0x01, 0x02 };
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));
    uint8_t neg_reply[2];
    read_exactly(client, neg_reply, sizeof(neg_reply));
    ck_assert_uint_eq(0x05, neg_reply[0]);
    ck_assert_uint_eq(0x02, neg_reply[1]);

    /* RFC 1929 auth: VER=1, ULEN=5 "alice", PLEN=6 "secret" */
    uint8_t auth[] = { 0x01, 0x05, 'a','l','i','c','e', 0x06, 's','e','c','r','e','t' };
    ck_assert_int_eq(write(client, auth, sizeof(auth)), (ssize_t)sizeof(auth));
    uint8_t auth_reply[2];
    read_exactly(client, auth_reply, sizeof(auth_reply));
    ck_assert_uint_eq(0x01, auth_reply[0]);
    ck_assert_uint_eq(0x00, auth_reply[1]); /* success */

    send_connect_ipv4(client, origin.port);
    ck_assert_uint_eq(SOCKS5_REP_SUCCESS, read_socks5_reply(client));

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    pthread_join(origin_tid, NULL);
    close(origin.listen_fd);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
    socks5_set_users(&no_users);
}
END_TEST

/* Invalid credentials get AUTH status 0x01 and the connection is closed (RFC
 * 1929) without ever reaching the request phase. */
START_TEST(test_socks5_userpass_invalid_rejected)
{
    static const struct socks5args args = { .users = { { .name = "alice", .pass = "secret" } } };
    socks5_set_users(&args);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    uint8_t neg[] = { 0x05, 0x01, 0x02 };
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));
    uint8_t neg_reply[2];
    read_exactly(client, neg_reply, sizeof(neg_reply));
    ck_assert_uint_eq(0x02, neg_reply[1]);

    /* wrong password */
    uint8_t auth[] = { 0x01, 0x05, 'a','l','i','c','e', 0x03, 'b','a','d' };
    ck_assert_int_eq(write(client, auth, sizeof(auth)), (ssize_t)sizeof(auth));
    uint8_t auth_reply[2];
    read_exactly(client, auth_reply, sizeof(auth_reply));
    ck_assert_uint_eq(0x01, auth_reply[0]);
    ck_assert_uint_eq(0x01, auth_reply[1]); /* failure */

    /* server must close after rejecting -> EOF */
    uint8_t scratch[8];
    ck_assert_int_eq(read(client, scratch, sizeof(scratch)), 0);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
    socks5_set_users(&no_users);
}
END_TEST

/* Pipelined client: negotiation + request arrive in a single segment. The
 * request bytes sit in the read buffer after negotiation finishes; the server
 * must still process them (no new readable event will come) and drive the
 * connection through to connect. */
START_TEST(test_socks5_pipelined_request)
{
    socks5_set_users(&no_users);

    struct origin_ctx origin = start_origin();
    pthread_t origin_tid;
    ck_assert_int_eq(pthread_create(&origin_tid, NULL, origin_echo_run, &origin), 0);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    /* negotiation (no-auth) + IPv4 CONNECT, all in one write() */
    uint8_t pipelined[13] = {
        0x05, 0x01, 0x00,                               /* negotiation */
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00 /* request */
    };
    encode_port(&pipelined[11], origin.port);
    ck_assert_int_eq(write(client, pipelined, sizeof(pipelined)),
                     (ssize_t)sizeof(pipelined));

    uint8_t reply[2];
    read_exactly(client, reply, sizeof(reply));
    ck_assert_uint_eq(0x05, reply[0]);
    ck_assert_uint_eq(0x00, reply[1]);

    /* the buffered request must have been processed -> SOCKS5 success reply */
    ck_assert_uint_eq(SOCKS5_REP_SUCCESS, read_socks5_reply(client));

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    pthread_join(origin_tid, NULL);
    close(origin.listen_fd);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* A client offering only an unsupported method (e.g. GSSAPI) must get
 * VER=5, METHOD=0xFF and then be closed (RFC 1928). */
START_TEST(test_socks5_no_acceptable_method_closes)
{
    socks5_set_users(&no_users);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    uint8_t neg[] = { 0x05, 0x01, 0x03 }; /* only GSSAPI */
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));

    uint8_t reply[2];
    read_exactly(client, reply, sizeof(reply));
    ck_assert_uint_eq(0x05, reply[0]);
    ck_assert_uint_eq(0xFF, reply[1]);

    uint8_t scratch[8];
    ck_assert_int_eq(read(client, scratch, sizeof(scratch)), 0); /* closed */

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* With users configured, a client that offers only no-auth cannot skip
 * authentication: it gets 0xFF and is closed. */
START_TEST(test_socks5_auth_required_rejects_noauth)
{
    static const struct socks5args args = { .users = { { .name = "alice", .pass = "secret" } } };
    socks5_set_users(&args);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    uint8_t neg[] = { 0x05, 0x01, 0x00 }; /* only no-auth */
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));

    uint8_t reply[2];
    read_exactly(client, reply, sizeof(reply));
    ck_assert_uint_eq(0x05, reply[0]);
    ck_assert_uint_eq(0xFF, reply[1]);

    uint8_t scratch[8];
    ck_assert_int_eq(read(client, scratch, sizeof(scratch)), 0);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
    socks5_set_users(&no_users);
}
END_TEST

/* A malformed request (bad RSV) must get a SOCKS5 failure reply (10 bytes,
 * REP != 0) before the connection is closed, mirroring how the negotiation and
 * auth phases reply. */
START_TEST(test_socks5_request_error_replies)
{
    socks5_set_users(&no_users);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    uint8_t neg[] = { 0x05, 0x01, 0x00 };
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));
    uint8_t neg_reply[2];
    read_exactly(client, neg_reply, sizeof(neg_reply));

    /* RSV must be 0x00; send 0xFF to force REQ_ERROR */
    uint8_t bad_req[] = { 0x05, 0x01, 0xFF, 0x01, 127, 0, 0, 1, 0x00, 0x50 };
    ck_assert_int_eq(write(client, bad_req, sizeof(bad_req)), (ssize_t)sizeof(bad_req));

    uint8_t rep[10];
    read_exactly(client, rep, sizeof(rep));
    ck_assert_uint_eq(0x05, rep[0]);
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE, rep[1]);
    ck_assert_uint_eq(0x00, rep[2]);          /* RSV */
    ck_assert_uint_eq(SOCKS5_ATYP_IPV4, rep[3]);

    uint8_t scratch[8];
    ck_assert_int_eq(read(client, scratch, sizeof(scratch)), 0);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* A non-CONNECT command (e.g. BIND) is unsupported: REP=0x07 then close. */
START_TEST(test_socks5_non_connect_rejected)
{
    socks5_set_users(&no_users);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    uint8_t neg[] = { 0x05, 0x01, 0x00 };
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));
    uint8_t neg_reply[2];
    read_exactly(client, neg_reply, sizeof(neg_reply));

    /* CMD=0x02 (BIND), otherwise a well-formed IPv4 request */
    uint8_t req[] = { 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 };
    ck_assert_int_eq(write(client, req, sizeof(req)), (ssize_t)sizeof(req));

    uint8_t rep[10];
    read_exactly(client, rep, sizeof(rep));
    ck_assert_uint_eq(0x05, rep[0]);
    ck_assert_uint_eq(SOCKS5_REP_CMD_NOT_SUPPORTED, rep[1]);

    uint8_t scratch[8];
    ck_assert_int_eq(read(client, scratch, sizeof(scratch)), 0);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* ======================================================== relay tests ===== */

/* Full relay: CONNECT to a live echo origin, send data, read it back. */
START_TEST(test_socks5_relay_echo)
{
    socks5_set_users(&no_users);

    struct origin_ctx origin = start_origin();
    pthread_t origin_tid;
    ck_assert_int_eq(pthread_create(&origin_tid, NULL, origin_echo_run, &origin), 0);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);
    negotiate_noauth(client);
    send_connect_ipv4(client, origin.port);
    ck_assert_uint_eq(SOCKS5_REP_SUCCESS, read_socks5_reply(client));

    /* Send some data through the relay and expect it echoed back. */
    const char *msg = "Hello, relay!";
    size_t msg_len = strlen(msg);
    ck_assert_int_eq(write(client, msg, msg_len), (ssize_t)msg_len);

    uint8_t echoed[64];
    read_exactly(client, echoed, msg_len);
    ck_assert_int_eq(memcmp(msg, echoed, msg_len), 0);

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    pthread_join(origin_tid, NULL);
    close(origin.listen_fd);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* CONNECT to a closed port: should get SOCKS5_REP_CONNECTION_REFUSED. */
START_TEST(test_socks5_connect_refused)
{
    socks5_set_users(&no_users);

    /* Open a listening socket, grab its port, then close it immediately —
     * this guarantees the port is closed when the proxy tries to connect. */
    struct origin_ctx origin = start_origin();
    unsigned short dead_port = origin.port;
    close(origin.listen_fd);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);
    negotiate_noauth(client);
    send_connect_ipv4(client, dead_port);

    uint8_t rep_code = read_socks5_reply(client);
    ck_assert_uint_eq(SOCKS5_REP_CONNECTION_REFUSED, rep_code);

    /* After the error reply the connection should close. */
    uint8_t scratch[8];
    ck_assert_int_eq(read(client, scratch, sizeof(scratch)), 0);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* A failed FQDN resolution is reported as general failure (REP=0x01), not as
 * host unreachable. */
START_TEST(test_socks5_fqdn_resolution_failure_is_general_failure)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 50000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    fd_selector s = selector_new(64);
    ck_assert_ptr_nonnull(s);

    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct socks5_conn *c = new_registered_test_conn(s, fds[0]);
    c->stm.current = &socks5_states[REQ_RESOLVE];

    struct selector_key key = {
        .s    = s,
        .fd   = c->client_fd,
        .data = c,
    };
    ck_assert_uint_eq(REQ_WRITE, request_resolve_done(&key));

    size_t pending;
    uint8_t *reply = buffer_read_ptr(&c->write_buffer, &pending);
    ck_assert_uint_eq(10, pending);
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE, reply[1]);

    selector_unregister_fd(s, fds[0]);
    ck_assert_uint_eq(0, socks5_active_connections());
    close(fds[1]);
    selector_destroy(s);
    selector_close();
}
END_TEST

/* FQDN CONNECT: resolve "localhost" and relay through the echo origin. This
 * exercises the DNS resolution thread and the REQ_RESOLVE → REQ_CONNECTING
 * path. */
START_TEST(test_socks5_fqdn_connect_and_relay)
{
    socks5_set_users(&no_users);

    struct origin_ctx origin = start_origin();
    pthread_t origin_tid;
    ck_assert_int_eq(pthread_create(&origin_tid, NULL, origin_echo_run, &origin), 0);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);
    negotiate_noauth(client);

    /* SOCKS5 CONNECT with ATYP=DOMAIN for "localhost" */
    const char *domain = "localhost";
    uint8_t dlen = (uint8_t)strlen(domain);
    uint8_t req[4 + 1 + 255 + 2]; /* VER CMD RSV ATYP DLEN domain PORT */
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03; /* ATYP DOMAIN */
    req[4] = dlen;
    memcpy(&req[5], domain, dlen);
    encode_port(&req[5 + dlen], origin.port);
    size_t req_len = 5 + dlen + 2;
    ck_assert_int_eq(write(client, req, req_len), (ssize_t)req_len);

    ck_assert_uint_eq(SOCKS5_REP_SUCCESS, read_socks5_reply(client));

    /* Relay data. */
    const char *msg = "DNS relay!";
    size_t msg_len = strlen(msg);
    ck_assert_int_eq(write(client, msg, msg_len), (ssize_t)msg_len);

    uint8_t echoed[64];
    read_exactly(client, echoed, msg_len);
    ck_assert_int_eq(memcmp(msg, echoed, msg_len), 0);

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    pthread_join(origin_tid, NULL);
    close(origin.listen_fd);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* ==================================== inactivity reaper tests =========== */

/* Una conexión idle por más de SOCKS5_INACTIVITY_TIMEOUT debe ser cosechada. */
START_TEST(test_socks5_reap_idle_connection)
{
    socks5_set_users(&no_users);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);
    /* Enviar sólo la negociación; después no hacer nada (simulando idle). */
    negotiate_noauth(client);

    /* Esperar un ciclo del selector para que la conexión procese la negociación. */
    sleep_ms(200);

    /* Forzar que la conexión parezca expirada: atrasar last_activity. */
    ck_assert_uint_ge(socks5_active_connections(), 1);
    struct socks5_conn *c = conn_list;
    ck_assert_ptr_nonnull(c);
    c->last_activity = time(NULL) - SOCKS5_INACTIVITY_TIMEOUT - 1;

    reap_last_sweep = 0; /* reset throttle para que el barrido corra */
    socks5_reap_idle(test_selector);

    ck_assert_uint_eq(socks5_active_connections(), 0);

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* RELAY tunnels can be idle for longer than the handshake timeout and still be
 * legitimate live connections.  Reaping must not close them. */
START_TEST(test_socks5_reap_does_not_close_idle_relay)
{
    socks5_set_users(&no_users);

    struct origin_ctx origin = start_origin();
    pthread_t origin_tid;
    ck_assert_int_eq(pthread_create(&origin_tid, NULL, origin_echo_run, &origin), 0);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);
    negotiate_noauth(client);
    send_connect_ipv4(client, origin.port);
    ck_assert_uint_eq(SOCKS5_REP_SUCCESS, read_socks5_reply(client));

    sleep_ms(200);
    struct socks5_conn *c = conn_list;
    ck_assert_ptr_nonnull(c);
    ck_assert_uint_eq(RELAY, stm_state(&c->stm));
    c->last_activity = time(NULL) - SOCKS5_INACTIVITY_TIMEOUT - 1;

    reap_last_sweep = 0;
    socks5_reap_idle(test_selector);
    ck_assert_uint_ge(socks5_active_connections(), 1);

    const char *msg = "still alive";
    size_t msg_len = strlen(msg);
    ck_assert_int_eq(write(client, msg, msg_len), (ssize_t)msg_len);

    uint8_t echoed[64];
    read_exactly(client, echoed, msg_len);
    ck_assert_int_eq(memcmp(msg, echoed, msg_len), 0);

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    pthread_join(origin_tid, NULL);
    close(origin.listen_fd);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

/* Expired connects should report a SOCKS5 failure reply instead of silently
 * dropping the client connection. */
START_TEST(test_socks5_reap_req_connecting_sends_failure_reply)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 50000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    fd_selector s = selector_new(64);
    ck_assert_ptr_nonnull(s);

    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct socks5_conn *c = new_registered_test_conn(s, fds[0]);
    c->stm.current = &socks5_states[REQ_CONNECTING];
    c->last_activity = time(NULL) - SOCKS5_INACTIVITY_TIMEOUT - 1;

    reap_last_sweep = 0;
    socks5_reap_idle(s);
    ck_assert_uint_eq(REQ_WRITE, stm_state(&c->stm));
    ck_assert_uint_eq(1, socks5_active_connections());

    struct selector_key key = {
        .s    = s,
        .fd   = c->client_fd,
        .data = c,
    };
    socks5_write(&key);

    uint8_t reply[10];
    read_exactly(fds[1], reply, sizeof(reply));
    ck_assert_uint_eq(SOCKS5_REP_TTL_EXPIRED, reply[1]);
    ck_assert_uint_eq(0, socks5_active_connections());

    close(fds[1]);
    selector_destroy(s);
    selector_close();
}
END_TEST

/* Una conexión en REQ_RESOLVE no debe ser cosechada, incluso si está expirada. */
START_TEST(test_socks5_reap_skips_req_resolve)
{
    socks5_set_users(&no_users);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    /* Esperar a que el accept cree la conexión. */
    sleep_ms(200);

    ck_assert_uint_ge(socks5_active_connections(), 1);
    struct socks5_conn *c = conn_list;
    ck_assert_ptr_nonnull(c);

    /* Forzar el estado a REQ_RESOLVE y expirar el last_activity.
     * current apunta a la tabla de estados indexada por el enum. */
    c->stm.current = &socks5_states[REQ_RESOLVE];
    c->last_activity = time(NULL) - SOCKS5_INACTIVITY_TIMEOUT - 100;

    reap_last_sweep = 0; /* reset throttle */
    socks5_reap_idle(test_selector);

    /* La conexión debe seguir viva a pesar de estar expirada. */
    ck_assert_uint_ge(socks5_active_connections(), 1);

    /* Limpieza: restaurar un estado que permita al reaper cerrar. */
    c->stm.current = &socks5_states[NEG_READ];
    c->last_activity = 0; /* asegurar expiración */
    reap_last_sweep = 0;
    socks5_reap_idle(test_selector);
    ck_assert_uint_eq(socks5_active_connections(), 0);

    close(client);
    test_stop = 1;
    pthread_join(loop, NULL);
    selector_destroy(test_selector);
    selector_close();
    close(passive);
}
END_TEST

static void *resolver_noop(void *unused)
{
    (void)unused;
    return NULL;
}

/* If the client fd is closed while a resolver reference is pending, close must
 * wait for that resolver and release the connection instead of leaking it. */
START_TEST(test_socks5_close_joins_pending_resolver_reference)
{
    struct selector_init conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 50000000 },
    };
    ck_assert_int_eq(selector_init(&conf), SELECTOR_SUCCESS);
    fd_selector s = selector_new(64);
    ck_assert_ptr_nonnull(s);

    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct socks5_conn *c = new_registered_test_conn(s, fds[0]);
    c->stm.current = &socks5_states[REQ_RESOLVE];
    c->references++;
    c->resolver_running = true;
    ck_assert_int_eq(pthread_create(&c->resolver_tid, NULL, resolver_noop, NULL), 0);

    ck_assert_uint_eq(1, socks5_active_connections());
    ck_assert_int_eq(selector_unregister_fd(s, fds[0]), SELECTOR_SUCCESS);
    ck_assert_uint_eq(0, socks5_active_connections());

    close(fds[1]);
    selector_destroy(s);
    selector_close();
}
END_TEST

/* ======================================================== suite ========= */

static Suite *socks5_suite(void)
{
    Suite *s  = suite_create("socks5");
    TCase *tc = tcase_create("stm");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_socks5_negotiation_then_connect);
    tcase_add_test(tc, test_socks5_bad_version_closes);
    tcase_add_test(tc, test_socks5_userpass_valid_advances);
    tcase_add_test(tc, test_socks5_userpass_invalid_rejected);
    tcase_add_test(tc, test_socks5_pipelined_request);
    tcase_add_test(tc, test_socks5_no_acceptable_method_closes);
    tcase_add_test(tc, test_socks5_auth_required_rejects_noauth);
    tcase_add_test(tc, test_socks5_request_error_replies);
    tcase_add_test(tc, test_socks5_non_connect_rejected);
    tcase_add_test(tc, test_socks5_relay_echo);
    tcase_add_test(tc, test_socks5_connect_refused);
    tcase_add_test(tc, test_socks5_fqdn_resolution_failure_is_general_failure);
    tcase_add_test(tc, test_socks5_fqdn_connect_and_relay);
    tcase_add_test(tc, test_socks5_reap_idle_connection);
    tcase_add_test(tc, test_socks5_reap_does_not_close_idle_relay);
    tcase_add_test(tc, test_socks5_reap_req_connecting_sends_failure_reply);
    tcase_add_test(tc, test_socks5_reap_skips_req_resolve);
    tcase_add_test(tc, test_socks5_close_joins_pending_resolver_reference);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(socks5_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
