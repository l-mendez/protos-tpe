#ifndef STRESS_RUNNER_SUPPORT_H
#define STRESS_RUNNER_SUPPORT_H

#include <stdbool.h>
#include <stddef.h>

bool stress_parse_proc_status(const char *text, unsigned long *rss_kib);
bool stress_parse_proc_stat(const char *text, unsigned long long *cpu_ticks);
void stress_append_failure(char *dst, size_t cap, const char *fmt, ...);

#endif
