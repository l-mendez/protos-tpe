#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "args.h"
#include "../src/server/runtime_users.h"
#include "../src/server/runtime_users.c"

static void
seed_users(void)
{
    struct users users[MAX_USERS] = {
        { .name = "alice", .pass = "secret" },
        { .name = "bob", .pass = "hunter2" },
    };
    runtime_users_init_from_args(users);
}

START_TEST(test_runtime_users_seed_and_validate)
{
    char matched[256];
    seed_users();

    ck_assert(runtime_users_auth_required());
    ck_assert_uint_eq(2, runtime_users_count());
    ck_assert(runtime_users_validate((const uint8_t *)"alice", 5,
                                     (const uint8_t *)"secret", 6,
                                     matched, sizeof(matched)));
    ck_assert_str_eq("alice", matched);
    ck_assert(!runtime_users_validate((const uint8_t *)"alice", 5,
                                      (const uint8_t *)"bad", 3,
                                      matched, sizeof(matched)));
}
END_TEST

START_TEST(test_runtime_users_add_delete_and_passwd)
{
    char list[256];
    runtime_users_clear();

    ck_assert(!runtime_users_auth_required());
    ck_assert_int_eq(RUNTIME_USER_OK, runtime_users_add("carol", "first"));
    ck_assert_int_eq(RUNTIME_USER_EXISTS, runtime_users_add("carol", "other"));
    ck_assert(runtime_users_auth_required());

    ck_assert(runtime_users_format_list(list, sizeof(list)));
    ck_assert_str_eq("carol", list);

    ck_assert_int_eq(RUNTIME_USER_OK, runtime_users_passwd("carol", "second"));
    ck_assert(runtime_users_validate((const uint8_t *)"carol", 5,
                                     (const uint8_t *)"second", 6,
                                     NULL, 0));
    ck_assert(!runtime_users_validate((const uint8_t *)"carol", 5,
                                      (const uint8_t *)"first", 5,
                                      NULL, 0));

    ck_assert_int_eq(RUNTIME_USER_OK, runtime_users_del("carol"));
    ck_assert_int_eq(RUNTIME_USER_NOT_FOUND, runtime_users_del("carol"));
    ck_assert(!runtime_users_auth_required());
}
END_TEST

START_TEST(test_runtime_users_reject_invalid_cli_tokens)
{
    runtime_users_clear();

    ck_assert_int_eq(RUNTIME_USER_INVALID, runtime_users_add("", "pass"));
    ck_assert_int_eq(RUNTIME_USER_INVALID, runtime_users_add("bad user", "pass"));
    ck_assert_int_eq(RUNTIME_USER_INVALID, runtime_users_add("user", ""));
    ck_assert_int_eq(RUNTIME_USER_INVALID, runtime_users_add("user", "bad pass"));
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("runtime_users");
    TCase *tc = tcase_create("runtime_users");
    tcase_add_test(tc, test_runtime_users_seed_and_validate);
    tcase_add_test(tc, test_runtime_users_add_delete_and_passwd);
    tcase_add_test(tc, test_runtime_users_reject_invalid_cli_tokens);
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
