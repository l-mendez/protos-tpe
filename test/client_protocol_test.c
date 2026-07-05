#include <stdlib.h>
#include <check.h>

#include "../src/client/client_protocol.h"
#include "../src/client/client_protocol.c"

START_TEST(test_client_builds_metrics)
{
    char out[128];
    char *argv[] = { "metrics" };

    ck_assert_int_eq(CLIENT_CMD_OK,
                     client_build_command(1, argv, out, sizeof(out)));
    ck_assert_str_eq("METRICS", out);
}
END_TEST

START_TEST(test_client_builds_users_and_config_commands)
{
    char out[128];
    char *add[] = { "users", "add", "bob", "hunter2" };
    char *passwd[] = { "users", "passwd", "bob", "newpass" };
    char *config[] = { "config", "set", "relay_idle_timeout_seconds", "120" };

    ck_assert_int_eq(CLIENT_CMD_OK,
                     client_build_command(4, add, out, sizeof(out)));
    ck_assert_str_eq("USERS ADD bob hunter2", out);

    ck_assert_int_eq(CLIENT_CMD_OK,
                     client_build_command(4, passwd, out, sizeof(out)));
    ck_assert_str_eq("USERS PASSWD bob newpass", out);

    ck_assert_int_eq(CLIENT_CMD_OK,
                     client_build_command(4, config, out, sizeof(out)));
    ck_assert_str_eq("CONFIG SET relay_idle_timeout_seconds 120", out);
}
END_TEST

START_TEST(test_client_rejects_bad_arity)
{
    char out[128];
    char *bad[] = { "users", "add", "bob" };

    ck_assert_int_eq(CLIENT_CMD_USAGE,
                     client_build_command(3, bad, out, sizeof(out)));
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("client_protocol");
    TCase *tc = tcase_create("client_protocol");
    tcase_add_test(tc, test_client_builds_metrics);
    tcase_add_test(tc, test_client_builds_users_and_config_commands);
    tcase_add_test(tc, test_client_rejects_bad_arity);
    suite_add_tcase(s, tc);
    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
