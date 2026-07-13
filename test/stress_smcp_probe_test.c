#include <check.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../stress/stress_helpers.c"
#include "../stress/smcp_probe.c"

static int make_listener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    ck_assert_int_eq(0, bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
    ck_assert_int_eq(0, listen(fd, 2));
    socklen_t len = sizeof(addr);
    ck_assert_int_eq(0, getsockname(fd, (struct sockaddr *)&addr, &len));
    *port = ntohs(addr.sin_port);
    return fd;
}

static void read_line_or_exit(int fd)
{
    char ch;
    do {
        if (read(fd, &ch, 1) != 1) _exit(2);
    } while (ch != '\n');
}

static void write_fragmented_or_exit(int fd, const char *text)
{
    for (const char *p = text; *p != '\0'; p++) {
        if (write(fd, p, 1) != 1) _exit(3);
    }
}

static void fake_smcp(int listener)
{
    int client = accept(listener, NULL, NULL);
    if (client < 0) _exit(1);
    read_line_or_exit(client);
    write_fragmented_or_exit(client, "+OK authenticated\n");
    read_line_or_exit(client);
    write_fragmented_or_exit(client,
        "+OK 7\n"
        "active_connections 500\n"
        "historical_connections 501\n"
        "max_active_connections 500\n"
        "bytes_client_to_origin 1024\n"
        "bytes_origin_to_client 2048\n"
        "total_bytes 3072\n"
        "users_count 1\n");
    read_line_or_exit(client);
    close(client);
    close(listener);
    _exit(0);
}

START_TEST(test_queries_fragmented_smcp_metrics)
{
    uint16_t port;
    int listener = make_listener(&port);
    pid_t child = fork();
    ck_assert_int_ge(child, 0);
    if (child == 0) fake_smcp(listener);
    close(listener);

    struct stress_metrics metrics;
    ck_assert(stress_smcp_query_metrics(port, &metrics));
    ck_assert_uint_eq(500, metrics.active_connections);
    ck_assert_uint_eq(500, metrics.max_active_connections);

    int status;
    ck_assert_int_eq(child, waitpid(child, &status, 0));
    ck_assert(WIFEXITED(status));
    ck_assert_int_eq(0, WEXITSTATUS(status));
}
END_TEST

int main(void)
{
    Suite *suite = suite_create("stress_smcp_probe");
    TCase *tc = tcase_create("probe");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_queries_fragmented_smcp_metrics);
    suite_add_tcase(suite, tc);
    SRunner *runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);
    int failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
