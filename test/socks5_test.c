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
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
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

/* A no-auth negotiation must be answered with VER=5, METHOD=0x00, and a valid
 * IPv4 CONNECT request must drive the connection to completion (the server
 * closes it -> client sees EOF), proving it advanced through the states. */
START_TEST(test_socks5_negotiation_then_request)
{
    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    /* negotiation: VER=5, NMETHODS=1, no-auth */
    uint8_t neg[] = { 0x05, 0x01, 0x00 };
    ck_assert_int_eq(write(client, neg, sizeof(neg)), (ssize_t)sizeof(neg));

    uint8_t reply[2];
    read_exactly(client, reply, sizeof(reply));
    ck_assert_uint_eq(0x05, reply[0]);
    ck_assert_uint_eq(0x00, reply[1]);

    /* request: IPv4 CONNECT 127.0.0.1:80 */
    uint8_t req[] = { 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 };
    ck_assert_int_eq(write(client, req, sizeof(req)), (ssize_t)sizeof(req));

    /* on REQ_DONE the server parks in DONE and closes -> read returns EOF (0) */
    uint8_t scratch[8];
    ssize_t r = read(client, scratch, sizeof(scratch));
    ck_assert_int_eq(r, 0);

    test_stop = 1;
    pthread_join(loop, NULL);
    close(client);
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
 * gets AUTH status 0x00 and advances to the request; the request then drives the
 * connection to completion (server closes -> EOF). */
START_TEST(test_socks5_userpass_valid_advances)
{
    static const struct socks5args args = { .users = { { .name = "alice", .pass = "secret" } } };
    socks5_set_users(&args);

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

    /* request: IPv4 CONNECT 127.0.0.1:80 -> server parks in DONE and closes */
    uint8_t req[] = { 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 };
    ck_assert_int_eq(write(client, req, sizeof(req)), (ssize_t)sizeof(req));
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
 * connection to completion. Guards against the level-triggered stall. */
START_TEST(test_socks5_pipelined_request)
{
    socks5_set_users(&no_users);

    int            passive;
    unsigned short port = start_server(&passive);

    test_stop = 0;
    pthread_t loop;
    ck_assert_int_eq(pthread_create(&loop, NULL, run_selector, NULL), 0);

    int client = connect_to(port);

    /* negotiation (no-auth) + IPv4 CONNECT, all in one write() */
    uint8_t pipelined[] = {
        0x05, 0x01, 0x00,                               /* negotiation */
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 /* request */
    };
    ck_assert_int_eq(write(client, pipelined, sizeof(pipelined)),
                     (ssize_t)sizeof(pipelined));

    uint8_t reply[2];
    read_exactly(client, reply, sizeof(reply));
    ck_assert_uint_eq(0x05, reply[0]);
    ck_assert_uint_eq(0x00, reply[1]);

    /* the buffered request must have been processed -> server closes -> EOF */
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

static Suite *socks5_suite(void)
{
    Suite *s  = suite_create("socks5");
    TCase *tc = tcase_create("stm");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_socks5_negotiation_then_request);
    tcase_add_test(tc, test_socks5_bad_version_closes);
    tcase_add_test(tc, test_socks5_userpass_valid_advances);
    tcase_add_test(tc, test_socks5_userpass_invalid_rejected);
    tcase_add_test(tc, test_socks5_pipelined_request);
    tcase_add_test(tc, test_socks5_no_acceptable_method_closes);
    tcase_add_test(tc, test_socks5_auth_required_rejects_noauth);
    tcase_add_test(tc, test_socks5_request_error_replies);
    tcase_add_test(tc, test_socks5_non_connect_rejected);
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
