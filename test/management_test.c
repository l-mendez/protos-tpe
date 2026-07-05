#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "args.h"
#include "../src/server/management.h"
#include "../src/server/metrics.h"
#include "../src/server/runtime_config.h"
#include "../src/server/runtime_users.h"
#include "../src/server/metrics.c"
#include "../src/server/runtime_config.c"
#include "../src/server/runtime_users.c"
#include "../src/server/management.c"

static void
reset_management_state(void)
{
    struct users users[MAX_USERS] = {
        { .name = "alice", .pass = "secret" },
    };
    runtime_users_init_from_args(users);
    runtime_config_init(true);
    metrics_reset();
    management_set_admin("admin", "token");
}

static void
dispatch(const char *line, char *out, size_t cap)
{
    management_dispatch_line(line, out, cap);
}

START_TEST(test_management_rejects_bad_auth)
{
    char out[512];

    reset_management_state();
    dispatch("AUTH admin wrong METRICS\n", out, sizeof(out));

    ck_assert_str_eq("ERR UNAUTHORIZED invalid credentials\n", out);
}
END_TEST

START_TEST(test_management_metrics_command)
{
    char out[512];

    reset_management_state();
    metrics_socks_connection_opened();
    metrics_add_client_to_origin_bytes(7);

    dispatch("AUTH admin token METRICS\n", out, sizeof(out));

    ck_assert_str_eq("OK socks_connections_total=1 socks_connections_current=1 "
                     "bytes_client_to_origin=7 bytes_origin_to_client=0 "
                     "bytes_total=7 auth_success_total=0 auth_failure_total=0 "
                     "connect_success_total=0 connect_failure_total=0\n",
                     out);
}
END_TEST

START_TEST(test_management_users_commands)
{
    char out[512];

    reset_management_state();
    dispatch("AUTH admin token USERS ADD bob hunter2\n", out, sizeof(out));
    ck_assert_str_eq("OK user added\n", out);
    ck_assert(runtime_users_validate((const uint8_t *)"bob", 3,
                                     (const uint8_t *)"hunter2", 7,
                                     NULL, 0));

    dispatch("AUTH admin token USERS PASSWD bob changed\n", out, sizeof(out));
    ck_assert_str_eq("OK password updated\n", out);
    ck_assert(runtime_users_validate((const uint8_t *)"bob", 3,
                                     (const uint8_t *)"changed", 7,
                                     NULL, 0));

    dispatch("AUTH admin token USERS LIST\n", out, sizeof(out));
    ck_assert_str_eq("OK alice bob\n", out);

    dispatch("AUTH admin token USERS DEL bob\n", out, sizeof(out));
    ck_assert_str_eq("OK user deleted\n", out);
}
END_TEST

START_TEST(test_management_config_commands)
{
    char out[512];

    reset_management_state();
    dispatch("AUTH admin token CONFIG GET disectors_enabled\n", out, sizeof(out));
    ck_assert_str_eq("OK true\n", out);

    dispatch("AUTH admin token CONFIG SET relay_idle_timeout_seconds 120\n",
             out, sizeof(out));
    ck_assert_str_eq("OK config updated\n", out);
    ck_assert_uint_eq(120, runtime_config_relay_idle_timeout_seconds());

    dispatch("AUTH admin token CONFIG SET relay_idle_timeout_seconds 0\n",
             out, sizeof(out));
    ck_assert_str_eq("ERR INVALID_VALUE invalid config value\n", out);
}
END_TEST

START_TEST(test_management_rejects_malformed_and_unknown)
{
    char out[512];

    reset_management_state();
    dispatch("METRICS\n", out, sizeof(out));
    ck_assert_str_eq("ERR BAD_REQUEST expected AUTH user pass command\n", out);

    dispatch("AUTH admin token WAT\n", out, sizeof(out));
    ck_assert_str_eq("ERR UNKNOWN_COMMAND unknown command\n", out);
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("management");
    TCase *tc = tcase_create("management");
    tcase_add_test(tc, test_management_rejects_bad_auth);
    tcase_add_test(tc, test_management_metrics_command);
    tcase_add_test(tc, test_management_users_commands);
    tcase_add_test(tc, test_management_config_commands);
    tcase_add_test(tc, test_management_rejects_malformed_and_unknown);
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
