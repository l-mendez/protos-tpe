#include <check.h>

#include <stdlib.h>
#include <string.h>

#include "../stress/runner_support.c"

START_TEST(test_parses_linux_rss_and_cpu_ticks)
{
    unsigned long rss;
    ck_assert(stress_parse_proc_status("Name:\tserver\nVmRSS:\t  4321 kB\n", &rss));
    ck_assert_uint_eq(4321, rss);

    const char *stat =
        "123 (server worker) S 1 2 3 4 5 6 7 8 9 10 120 30 0 0 0 0 0";
    unsigned long long ticks;
    ck_assert(stress_parse_proc_stat(stat, &ticks));
    ck_assert_uint_eq(150, ticks);
}
END_TEST

START_TEST(test_appends_failures_without_overflow)
{
    char failures[24] = "first";
    stress_append_failure(failures, sizeof(failures), "second %d", 2);
    ck_assert_str_eq("first; second 2", failures);
    stress_append_failure(failures, sizeof(failures), "this is too long");
    ck_assert_int_eq('\0', failures[sizeof(failures) - 1]);
}
END_TEST

int main(void)
{
    Suite *suite = suite_create("stress_runner_support");
    TCase *tc = tcase_create("support");
    tcase_add_test(tc, test_parses_linux_rss_and_cpu_ticks);
    tcase_add_test(tc, test_appends_failures_without_overflow);
    suite_add_tcase(suite, tc);
    SRunner *runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);
    int failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
