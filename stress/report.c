#include "report.h"

#include "stress_helpers.h"

#include <inttypes.h>

static const char *status(bool passed)
{
    return passed ? "pass" : "fail";
}

bool stress_summarize_throughput(struct stress_results *r)
{
    if (r == NULL || r->throughput_count == 0) return false;
    r->throughput_summary_count = 0;
    for (size_t level = 0; level < STRESS_THROUGHPUT_LEVEL_COUNT; level++) {
        double values[STRESS_THROUGHPUT_REPETITIONS];
        size_t count = 0;
        bool passed = true;
        for (size_t i = 0; i < r->throughput_count; i++) {
            if (r->throughput[i].concurrency != STRESS_THROUGHPUT_LEVELS[level]) continue;
            if (count >= STRESS_THROUGHPUT_REPETITIONS) return false;
            values[count++] = r->throughput[i].mib_per_second;
            passed = passed && r->throughput[i].passed;
        }
        if (count == 0) continue;
        struct stress_throughput_summary *summary =
            &r->throughput_summary[r->throughput_summary_count++];
        summary->concurrency = STRESS_THROUGHPUT_LEVELS[level];
        summary->median_mib_per_second = stress_median(values, count);
        summary->passed = passed;
    }
    if (r->throughput_summary_count == 0 ||
        r->throughput_summary[0].median_mib_per_second <= 0.0) return false;
    const double baseline = r->throughput_summary[0].median_mib_per_second;
    for (size_t i = 0; i < r->throughput_summary_count; i++) {
        r->throughput_summary[i].degradation_percent =
            (baseline - r->throughput_summary[i].median_mib_per_second) * 100.0 / baseline;
    }
    return true;
}

bool stress_report_json(FILE *out, const struct stress_results *r)
{
    if (out == NULL || r == NULL) return false;
    if (fputs("{\n  \"timestamp_utc\": ", out) < 0 ||
        !stress_json_string(out, r->timestamp_utc) ||
        fputs(",\n  \"system\": ", out) < 0 ||
        !stress_json_string(out, r->system) ||
        fputs(",\n  \"failures\": ", out) < 0 ||
        !stress_json_string(out, r->failures)) return false;
    if (fprintf(out,
                ",\n  \"open_file_limit\": %lu,\n"
                "  \"passed\": %s,\n"
                "  \"capacity\": {\"passed\": %s, \"connected\": %zu, "
                "\"observed_max\": %zu, \"lower_bound\": %s},\n"
                "  \"throughput\": [\n",
                r->open_file_limit, r->passed ? "true" : "false",
                r->capacity_passed ? "true" : "false", r->capacity_connected,
                r->observed_max, r->observed_max_is_lower_bound ? "true" : "false") < 0)
        return false;
    for (size_t i = 0; i < r->throughput_count; i++) {
        const struct stress_throughput_result *run = &r->throughput[i];
        if (fprintf(out,
                    "    {\"concurrency\": %zu, \"repetition\": %u, "
                    "\"bytes\": %" PRIu64 ", \"seconds\": %.6f, "
                    "\"mib_per_second\": %.3f, \"passed\": %s}%s\n",
                    run->concurrency, run->repetition, run->bytes, run->seconds,
                    run->mib_per_second, run->passed ? "true" : "false",
                    i + 1 == r->throughput_count ? "" : ",") < 0)
            return false;
    }
    if (fputs("  ],\n  \"throughput_summary\": [\n", out) < 0) return false;
    for (size_t i = 0; i < r->throughput_summary_count; i++) {
        const struct stress_throughput_summary *summary = &r->throughput_summary[i];
        if (fprintf(out,
                    "    {\"concurrency\": %zu, \"median_mib_per_second\": %.3f, "
                    "\"degradation_percent\": %.3f, \"passed\": %s}%s\n",
                    summary->concurrency, summary->median_mib_per_second,
                    summary->degradation_percent, summary->passed ? "true" : "false",
                    i + 1 == r->throughput_summary_count ? "" : ",") < 0) return false;
    }
    return fprintf(out,
                   "  ],\n  \"soak\": {\"passed\": %s, "
                   "\"rss_start_kib\": %lu, \"rss_max_kib\": %lu, "
                   "\"rss_end_kib\": %lu, \"cpu_seconds\": %.3f}\n}\n",
                   r->soak_passed ? "true" : "false", r->soak_rss_start_kib,
                   r->soak_rss_max_kib, r->soak_rss_end_kib,
                   r->soak_cpu_seconds) >= 0;
}

bool stress_report_csv(FILE *out, const struct stress_results *r)
{
    if (out == NULL || r == NULL ||
        fputs("concurrency,repetition,bytes,seconds,mib_per_second,status\n", out) < 0)
        return false;
    for (size_t i = 0; i < r->throughput_count; i++) {
        const struct stress_throughput_result *run = &r->throughput[i];
        if (fprintf(out, "%zu,%u,%" PRIu64 ",%.6f,%.6f,%s\n",
                    run->concurrency, run->repetition, run->bytes, run->seconds,
                    run->mib_per_second, status(run->passed)) < 0)
            return false;
    }
    return true;
}

bool stress_report_markdown(FILE *out, const struct stress_results *r)
{
    if (out == NULL || r == NULL) return false;
    if (fprintf(out,
                "# Resultados de stress SOCKS5\n\n"
                "- Fecha UTC: `%s`\n"
                "- Sistema: `%s`\n"
                "- Límite de archivos abiertos: `%lu`\n"
                "- Resultado global: **%s**\n"
                "- Fallos: `%s`\n\n"
                "## Capacidad\n\n"
                "| Métrica | Valor |\n|---|---:|\n"
                "| Gate de 500 conexiones | %s |\n"
                "| Conexiones verificadas | %zu |\n"
                "| Máximo observado | %zu%s |\n\n"
                "## Throughput\n\n"
                "| Concurrencia | Repetición | MiB/s por dirección | Estado |\n"
                "|---:|---:|---:|---|\n",
                r->timestamp_utc, r->system, r->open_file_limit,
                status(r->passed), r->failures[0] == '\0' ? "ninguno" : r->failures,
                status(r->capacity_passed),
                r->capacity_connected, r->observed_max,
                r->observed_max_is_lower_bound ? "+" : "") < 0)
        return false;
    for (size_t i = 0; i < r->throughput_count; i++) {
        const struct stress_throughput_result *run = &r->throughput[i];
        if (fprintf(out, "| %zu | %u | %.3f | %s |\n", run->concurrency,
                    run->repetition, run->mib_per_second, status(run->passed)) < 0)
            return false;
    }
    if (fputs("\n### Resumen\n\n"
              "| Concurrencia | Mediana MiB/s | Degradación | Estado |\n"
              "|---:|---:|---:|---|\n", out) < 0) return false;
    for (size_t i = 0; i < r->throughput_summary_count; i++) {
        const struct stress_throughput_summary *summary = &r->throughput_summary[i];
        if (fprintf(out, "| %zu | %.3f | %.2f%% | %s |\n", summary->concurrency,
                    summary->median_mib_per_second, summary->degradation_percent,
                    status(summary->passed)) < 0) return false;
    }
    return fprintf(out,
                   "\n## Soak\n\n"
                   "- Estado: **%s**\n"
                   "- RSS inicial/máximo/final: `%lu / %lu / %lu KiB`\n"
                   "- CPU consumida por el proxy: `%.3f s`\n\n"
                   "## Limitaciones\n\n"
                   "Las mediciones usan loopback y comparan degradación relativa; "
                   "no representan capacidad absoluta de red. Esta batería cubre "
                   "IPv4 con autenticación RFC 1929 y no cubre FQDN/DNS.\n",
                   status(r->soak_passed), r->soak_rss_start_kib,
                   r->soak_rss_max_kib, r->soak_rss_end_kib,
                   r->soak_cpu_seconds) >= 0;
}
