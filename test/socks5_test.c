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
#include "../src/server/socks5.c"

static fd_selector           test_selector;
static volatile sig_atomic_t test_stop;

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

static Suite *socks5_suite(void)
{
    Suite *s  = suite_create("socks5");
    TCase *tc = tcase_create("stm");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_socks5_negotiation_then_request);
    tcase_add_test(tc, test_socks5_bad_version_closes);
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
