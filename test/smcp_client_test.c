#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <check.h>

#include "../src/client/smcp_client.c"

static char *
read_file(FILE *f, char *buf, size_t cap)
{
    long n;
    rewind(f);
    n = ftell(f);
    (void)n;
    size_t got = fread(buf, 1, cap - 1, f);
    buf[got] = '\0';
    return buf;
}

static void
write_peer_response(int fd, const char *response)
{
    ck_assert_int_eq(write(fd, response, strlen(response)), (ssize_t)strlen(response));
}

static void
read_peer_command(int fd, char *buf, size_t cap)
{
    ssize_t n = read(fd, buf, cap - 1);
    ck_assert_int_gt(n, 0);
    buf[n] = '\0';
}

START_TEST(test_token_validation)
{
    ck_assert(smcp_is_token("admin"));
    ck_assert(smcp_is_token("a:b"));
    ck_assert(!smcp_is_token(""));
    ck_assert(!smcp_is_token("bad token"));
    ck_assert(!smcp_is_token("bad\ttoken"));
}
END_TEST

START_TEST(test_parse_count_status)
{
    unsigned long n = 0;
    ck_assert(smcp_parse_count_status("+OK 2", &n));
    ck_assert_uint_eq(2, n);
    ck_assert(!smcp_parse_count_status("+OK authenticated", &n));
    ck_assert(!smcp_parse_count_status("+OK 2 extra", &n));
    ck_assert(!smcp_parse_count_status("-ERR bad credentials", &n));
}
END_TEST

START_TEST(test_metrics_command_sends_line_and_reads_counted_response)
{
    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    FILE *out = tmpfile();
    FILE *err = tmpfile();
    ck_assert_ptr_nonnull(out);
    ck_assert_ptr_nonnull(err);

    write_peer_response(fds[1], "+OK 2\none\ntwo\n");
    ck_assert_int_eq(SMCP_RESULT_OK,
                     smcp_cmd_metrics(fds[0], false, out, err));

    char cmd[128];
    read_peer_command(fds[1], cmd, sizeof(cmd));
    ck_assert_str_eq("METRICS\n", cmd);

    char text[512];
    read_file(out, text, sizeof(text));
    ck_assert_str_eq("one\ntwo\n", text);

    fclose(out);
    fclose(err);
    close(fds[0]);
    close(fds[1]);
}
END_TEST

START_TEST(test_add_user_sends_real_password_and_prints_only_response)
{
    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    FILE *out = tmpfile();
    FILE *err = tmpfile();
    ck_assert_ptr_nonnull(out);
    ck_assert_ptr_nonnull(err);

    write_peer_response(fds[1], "+OK user added\n");
    ck_assert_int_eq(SMCP_RESULT_OK,
                     smcp_cmd_add_user(fds[0], "alice", "secret", false, out, err));

    char cmd[128];
    read_peer_command(fds[1], cmd, sizeof(cmd));
    ck_assert_str_eq("ADD-USER alice secret\n", cmd);

    char text[512];
    read_file(out, text, sizeof(text));
    ck_assert_str_eq("user added\n", text);
    ck_assert_ptr_null(strstr(text, "secret"));

    fclose(out);
    fclose(err);
    close(fds[0]);
    close(fds[1]);
}
END_TEST

START_TEST(test_verbose_shows_command_and_raw_status)
{
    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    FILE *out = tmpfile();
    FILE *err = tmpfile();
    ck_assert_ptr_nonnull(out);
    ck_assert_ptr_nonnull(err);

    write_peer_response(fds[1], "+OK 1\none\n");
    ck_assert_int_eq(SMCP_RESULT_OK,
                     smcp_cmd_metrics(fds[0], true, out, err));

    char cmd[128];
    read_peer_command(fds[1], cmd, sizeof(cmd));
    ck_assert_str_eq("METRICS\n", cmd);

    char text[512];
    read_file(out, text, sizeof(text));
    ck_assert_ptr_nonnull(strstr(text, "Command\n  METRICS\n"));
    ck_assert_ptr_nonnull(strstr(text, "Response\n  +OK 1\n  one\n"));

    fclose(out);
    fclose(err);
    close(fds[0]);
    close(fds[1]);
}
END_TEST

START_TEST(test_server_error_keeps_session_usable)
{
    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    FILE *out = tmpfile();
    FILE *err = tmpfile();
    ck_assert_ptr_nonnull(out);
    ck_assert_ptr_nonnull(err);

    write_peer_response(fds[1], "-ERR user exists\n+OK 1\nactive_connections 0\n");
    ck_assert_int_eq(SMCP_RESULT_REJECTED,
                     smcp_cmd_add_user(fds[0], "alice", "secret", false, out, err));
    ck_assert_int_eq(SMCP_RESULT_OK,
                     smcp_cmd_metrics(fds[0], false, out, err));

    char commands[128];
    read_peer_command(fds[1], commands, sizeof(commands));
    ck_assert_ptr_nonnull(strstr(commands, "ADD-USER alice secret\n"));

    char text[512];
    read_file(err, text, sizeof(text));
    ck_assert_ptr_nonnull(strstr(text, "user exists\n"));
    read_file(out, text, sizeof(text));
    ck_assert_ptr_nonnull(strstr(text, "active_connections 0\n"));

    fclose(out);
    fclose(err);
    close(fds[0]);
    close(fds[1]);
}
END_TEST

START_TEST(test_auth_consumes_optional_greeting_with_response)
{
    int fds[2];
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    FILE *out = tmpfile();
    FILE *err = tmpfile();
    ck_assert_ptr_nonnull(out);
    ck_assert_ptr_nonnull(err);

    write_peer_response(fds[1], "+OK SMCP 1.0 ready\n+OK authenticated\n");
    ck_assert_int_eq(SMCP_RESULT_OK,
                     smcp_cmd_auth(fds[0], "admin", "secret", false, out, err));

    char command[128];
    read_peer_command(fds[1], command, sizeof(command));
    ck_assert_str_eq("AUTH admin secret\n", command);

    char text[512];
    read_file(out, text, sizeof(text));
    ck_assert_str_eq("authenticated\n", text);

    fclose(out);
    fclose(err);
    close(fds[0]);
    close(fds[1]);
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("smcp_client");
    TCase *tc = tcase_create("smcp_client");

    tcase_add_test(tc, test_token_validation);
    tcase_add_test(tc, test_parse_count_status);
    tcase_add_test(tc, test_metrics_command_sends_line_and_reads_counted_response);
    tcase_add_test(tc, test_add_user_sends_real_password_and_prints_only_response);
    tcase_add_test(tc, test_verbose_shows_command_and_raw_status);
    tcase_add_test(tc, test_server_error_keeps_session_usable);
    tcase_add_test(tc, test_auth_consumes_optional_greeting_with_response);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void)
{
    SRunner *sr = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
