#include <check.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../stress/stress_helpers.c"
#include "../stress/loadgen.c"

static int read_exact(int fd, void *dst, size_t len)
{
    uint8_t *p = dst;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int fake_proxy_listener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    ck_assert_int_eq(0, bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
    ck_assert_int_eq(0, listen(fd, 4));
    socklen_t len = sizeof(addr);
    ck_assert_int_eq(0, getsockname(fd, (struct sockaddr *)&addr, &len));
    *port = ntohs(addr.sin_port);
    return fd;
}

static void fake_proxy_run(int listener, bool corrupt)
{
    int client = accept(listener, NULL, NULL);
    if (client < 0) _exit(2);
    uint8_t buf[520];
    if (read_exact(client, buf, 3) < 0) _exit(3);
    const uint8_t negotiation[] = {0x05, 0x02};
    if (write(client, negotiation, 1) != 1 || write(client, negotiation + 1, 1) != 1)
        _exit(4);
    const size_t auth_len = 3 + strlen(STRESS_PROXY_USER) + strlen(STRESS_PROXY_PASS);
    if (read_exact(client, buf, auth_len) < 0) _exit(5);
    const uint8_t auth[] = {0x01, 0x00};
    if (write(client, auth, sizeof(auth)) != (ssize_t)sizeof(auth)) _exit(6);
    if (read_exact(client, buf, 10) < 0) _exit(7);
    const uint8_t connected[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(connected); i++) {
        if (write(client, connected + i, 1) != 1) _exit(8);
    }
    ssize_t n = read(client, buf, sizeof(buf));
    if (n <= 0) _exit(9);
    if (corrupt) buf[0] ^= 0xffu;
    if (write(client, buf, (size_t)n) != n) _exit(10);
    while (read(client, buf, sizeof(buf)) > 0) {
    }
    close(client);
    close(listener);
    _exit(0);
}

static struct stress_load_event run_one_client(bool corrupt, int *load_status)
{
    uint16_t proxy_port;
    int listener = fake_proxy_listener(&proxy_port);
    pid_t child = fork();
    ck_assert_int_ge(child, 0);
    if (child == 0) fake_proxy_run(listener, corrupt);
    close(listener);

    int events[2];
    ck_assert_int_eq(0, pipe(events));
    struct stress_load_config config = {
        .mode = STRESS_LOAD_THROUGHPUT,
        .proxy_port = proxy_port,
        .target_port = 8080,
        .concurrency = 1,
        .total_bytes = 128,
        .event_fd = events[1],
        .control_fd = -1,
    };
    *load_status = stress_load_run(&config);
    close(events[1]);
    struct stress_load_event event, done = {0};
    while (read_exact(events[0], &event, sizeof(event)) == 0) {
        if (event.type == STRESS_LOAD_DONE) done = event;
    }
    close(events[0]);
    int status;
    ck_assert_int_eq(child, waitpid(child, &status, 0));
    ck_assert(WIFEXITED(status));
    ck_assert_int_eq(0, WEXITSTATUS(status));
    return done;
}

START_TEST(test_fragmented_handshake_preserves_connected_count)
{
    int status;
    struct stress_load_event done = run_one_client(false, &status);
    ck_assert_int_eq(0, status);
    ck_assert_uint_eq(1, done.connected);
    ck_assert_uint_eq(128, done.bytes);
}
END_TEST

START_TEST(test_corrupt_echo_is_reported)
{
    int status;
    struct stress_load_event done = run_one_client(true, &status);
    ck_assert_int_ne(0, status);
    ck_assert_uint_eq(1, done.corrupted);
}
END_TEST

int main(void)
{
    Suite *suite = suite_create("stress_loadgen");
    TCase *tc = tcase_create("integration");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_fragmented_handshake_preserves_connected_count);
    tcase_add_test(tc, test_corrupt_echo_is_reported);
    suite_add_tcase(suite, tc);
    SRunner *runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);
    int failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
