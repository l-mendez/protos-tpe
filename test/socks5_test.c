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
    tcase_add_test(tc, test_socks5_fqdn_connect_and_relay);
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
