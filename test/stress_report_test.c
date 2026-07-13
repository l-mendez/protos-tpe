#include <check.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../stress/stress_helpers.c"
#include "../stress/report.c"

static void read_file(FILE *f, char *dst, size_t cap)
{
    rewind(f);
    size_t n = fread(dst, 1, cap - 1, f);
    dst[n] = '\0';
}

START_TEST(test_renders_machine_and_human_readable_reports)
{
    struct stress_results results = {0};
    snprintf(results.timestamp_utc, sizeof(results.timestamp_utc),
             "2026-07-12T12:00:00Z");
    snprintf(results.system, sizeof(results.system), "Linux test");
    results.passed = true;
    results.capacity_passed = true;
    results.capacity_connected = 500;
    results.observed_max = 507;
    results.throughput_count = 1;
    results.throughput[0] = (struct stress_throughput_result){
        .concurrency = 50,
        .repetition = 2,
        .bytes = 67108864,
        .seconds = 2.0,
        .mib_per_second = 32.0,
        .passed = true,
    };
    results.soak_passed = true;
    results.soak_rss_start_kib = 1000;
    results.soak_rss_max_kib = 1200;
    results.soak_rss_end_kib = 1100;

    FILE *json = tmpfile(), *csv = tmpfile(), *markdown = tmpfile();
    ck_assert_ptr_nonnull(json);
    ck_assert_ptr_nonnull(csv);
    ck_assert_ptr_nonnull(markdown);
    ck_assert(stress_report_json(json, &results));
    ck_assert(stress_report_csv(csv, &results));
    ck_assert(stress_report_markdown(markdown, &results));

    char text[4096];
    read_file(json, text, sizeof(text));
    ck_assert_ptr_nonnull(strstr(text, "\"observed_max\": 507"));
    ck_assert_ptr_nonnull(strstr(text, "\"mib_per_second\": 32.000"));
    read_file(csv, text, sizeof(text));
    ck_assert_ptr_nonnull(strstr(text, "50,2,67108864,2.000000,32.000000,pass"));
    read_file(markdown, text, sizeof(text));
    ck_assert_ptr_nonnull(strstr(text, "Máximo observado | 507"));
    ck_assert_ptr_nonnull(strstr(text, "Limitaciones"));

    fclose(json);
    fclose(csv);
    fclose(markdown);
}
END_TEST

START_TEST(test_summarizes_throughput_with_median_and_degradation)
{
    struct stress_results results = {0};
    results.throughput_count = 6;
    const double rates[] = {10.0, 12.0, 11.0, 8.0, 9.0, 7.0};
    for (size_t i = 0; i < 6; i++) {
        results.throughput[i] = (struct stress_throughput_result){
            .concurrency = i < 3 ? 1 : 50,
            .repetition = (unsigned)(i % 3 + 1),
            .mib_per_second = rates[i],
            .passed = true,
        };
    }

    ck_assert(stress_summarize_throughput(&results));
    ck_assert_uint_eq(2, results.throughput_summary_count);
    ck_assert_uint_eq(1, results.throughput_summary[0].concurrency);
    ck_assert_double_eq_tol(11.0,
                            results.throughput_summary[0].median_mib_per_second,
                            0.0001);
    ck_assert_double_eq_tol(8.0,
                            results.throughput_summary[1].median_mib_per_second,
                            0.0001);
    ck_assert_double_eq_tol(27.2727,
                            results.throughput_summary[1].degradation_percent,
                            0.001);
}
END_TEST

static Suite *report_suite(void)
{
    Suite *suite = suite_create("stress_report");
    TCase *tc = tcase_create("render");
    tcase_add_test(tc, test_renders_machine_and_human_readable_reports);
    tcase_add_test(tc, test_summarizes_throughput_with_median_and_degradation);
    suite_add_tcase(suite, tc);
    return suite;
}

int main(void)
{
    SRunner *runner = srunner_create(report_suite());
    srunner_run_all(runner, CK_NORMAL);
    int failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
