#include <stdlib.h>
#include <check.h>

#include "../src/server/runtime_config.h"
#include "../src/server/runtime_config.c"

START_TEST(test_runtime_config_defaults_and_get)
{
    char value[64];

    runtime_config_init(false);

    ck_assert(runtime_config_get("disectors_enabled", value, sizeof(value)));
    ck_assert_str_eq("false", value);
    ck_assert(runtime_config_get("handshake_timeout_seconds", value, sizeof(value)));
    ck_assert_str_eq("60", value);
    ck_assert(runtime_config_get("relay_idle_timeout_seconds", value, sizeof(value)));
    ck_assert_str_eq("900", value);
}
END_TEST

START_TEST(test_runtime_config_set_valid_values)
{
    char value[64];

    runtime_config_init(true);

    ck_assert_int_eq(RUNTIME_CONFIG_OK,
                     runtime_config_set("disectors_enabled", "false"));
    ck_assert_int_eq(RUNTIME_CONFIG_OK,
                     runtime_config_set("handshake_timeout_seconds", "120"));
    ck_assert_int_eq(RUNTIME_CONFIG_OK,
                     runtime_config_set("relay_idle_timeout_seconds", "600"));

    ck_assert(runtime_config_get("disectors_enabled", value, sizeof(value)));
    ck_assert_str_eq("false", value);
    ck_assert_uint_eq(120, runtime_config_handshake_timeout_seconds());
    ck_assert_uint_eq(600, runtime_config_relay_idle_timeout_seconds());
}
END_TEST

START_TEST(test_runtime_config_rejects_invalid_values)
{
    runtime_config_init(true);

    ck_assert_int_eq(RUNTIME_CONFIG_NOT_FOUND,
                     runtime_config_set("missing", "1"));
    ck_assert_int_eq(RUNTIME_CONFIG_INVALID,
                     runtime_config_set("disectors_enabled", "maybe"));
    ck_assert_int_eq(RUNTIME_CONFIG_INVALID,
                     runtime_config_set("handshake_timeout_seconds", "0"));
    ck_assert_int_eq(RUNTIME_CONFIG_INVALID,
                     runtime_config_set("relay_idle_timeout_seconds", "999999"));
}
END_TEST

START_TEST(test_runtime_config_format_list)
{
    char payload[256];

    runtime_config_init(true);

    ck_assert(runtime_config_format_list(payload, sizeof(payload)));
    ck_assert_str_eq("disectors_enabled=true handshake_timeout_seconds=60 relay_idle_timeout_seconds=900",
                     payload);
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("runtime_config");
    TCase *tc = tcase_create("runtime_config");
    tcase_add_test(tc, test_runtime_config_defaults_and_get);
    tcase_add_test(tc, test_runtime_config_set_valid_values);
    tcase_add_test(tc, test_runtime_config_rejects_invalid_values);
    tcase_add_test(tc, test_runtime_config_format_list);
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
