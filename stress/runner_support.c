#include "runner_support.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool stress_parse_proc_status(const char *text, unsigned long *rss_kib)
{
    if (text == NULL || rss_kib == NULL) return false;
    const char *line = strstr(text, "VmRSS:");
    if (line == NULL) return false;
    char *end = NULL;
    unsigned long value = strtoul(line + strlen("VmRSS:"), &end, 10);
    if (end == line + strlen("VmRSS:") || strncmp(end, " kB", 3) != 0) return false;
    *rss_kib = value;
    return true;
}

bool stress_parse_proc_stat(const char *text, unsigned long long *cpu_ticks)
{
    if (text == NULL || cpu_ticks == NULL) return false;
    const char *p = strrchr(text, ')');
    if (p == NULL || p[1] != ' ' || p[2] == '\0') return false;
    p += 3; /* field 4 follows the state (field 3) and a space */
    for (unsigned field = 4; field <= 13; field++) {
        char *end = NULL;
        (void)strtoull(p, &end, 10);
        if (end == p || (*end != ' ' && *end != '\0')) return false;
        p = *end == ' ' ? end + 1 : end;
    }
    char *end = NULL;
    unsigned long long user = strtoull(p, &end, 10);
    if (end == p || *end != ' ') return false;
    p = end + 1;
    unsigned long long system = strtoull(p, &end, 10);
    if (end == p || (*end != ' ' && *end != '\0')) return false;
    *cpu_ticks = user + system;
    return true;
}

void stress_append_failure(char *dst, size_t cap, const char *fmt, ...)
{
    if (dst == NULL || cap == 0 || fmt == NULL) return;
    size_t used = strnlen(dst, cap);
    if (used >= cap) {
        dst[cap - 1] = '\0';
        return;
    }
    if (used > 0 && used + 2 < cap) {
        dst[used++] = ';';
        dst[used++] = ' ';
        dst[used] = '\0';
    }
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(dst + used, cap - used, fmt, args);
    va_end(args);
}
