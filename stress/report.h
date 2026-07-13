#ifndef STRESS_REPORT_H
#define STRESS_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "stress_config.h"

#define STRESS_MAX_THROUGHPUT_RESULTS \
    (STRESS_THROUGHPUT_LEVEL_COUNT * STRESS_THROUGHPUT_REPETITIONS)

struct stress_throughput_result {
    size_t concurrency;
    unsigned repetition;
    uint64_t bytes;
    double seconds;
    double mib_per_second;
    bool passed;
};

struct stress_throughput_summary {
    size_t concurrency;
    double median_mib_per_second;
    double degradation_percent;
    bool passed;
};

struct stress_results {
    char timestamp_utc[32];
    char system[256];
    char failures[2048];
    unsigned long open_file_limit;
    bool passed;
    bool capacity_passed;
    size_t capacity_connected;
    size_t observed_max;
    bool observed_max_is_lower_bound;
    struct stress_throughput_result throughput[STRESS_MAX_THROUGHPUT_RESULTS];
    size_t throughput_count;
    struct stress_throughput_summary throughput_summary[STRESS_THROUGHPUT_LEVEL_COUNT];
    size_t throughput_summary_count;
    bool soak_passed;
    unsigned long soak_rss_start_kib;
    unsigned long soak_rss_max_kib;
    unsigned long soak_rss_end_kib;
    double soak_cpu_seconds;
};

bool stress_summarize_throughput(struct stress_results *results);
bool stress_report_json(FILE *out, const struct stress_results *results);
bool stress_report_csv(FILE *out, const struct stress_results *results);
bool stress_report_markdown(FILE *out, const struct stress_results *results);

#endif
