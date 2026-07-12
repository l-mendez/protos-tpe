#include <string.h>
#include <time.h>

#include "access_log.h"

bool
access_log_open(struct AccessLog *l, const char *path)
{
    snprintf(l->path, sizeof(l->path), "%s", path);
    l->fp = fopen(path, "a");
    return l->fp != NULL;
}

void
access_log_close(struct AccessLog *l)
{
    if (l->fp != NULL) {
        fclose(l->fp);
        l->fp = NULL;
    }
}

void
access_log_record(struct AccessLog *l, const char *user,
                  const char *dest, const char *result)
{
    if (l->fp == NULL) {
        return;
    }
    // wallclock
    char       ts[32];
    time_t     now = time(NULL);
    struct tm  tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    fprintf(l->fp, "%s %s CONNECT %s %s\n", ts, user, dest, result);
    fflush(l->fp); /* durabilidad: el registro queda en el archivo de inmediato */
}

/* Quita el '\n' final (y un '\r' previo) de la línea, in situ. */
static void strip_newline(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

size_t
access_log_tail(const struct AccessLog *l, size_t n,
                char lines[][ACCESS_LOG_LINE_MAX], size_t cap)
{
    size_t want = n < cap ? n : cap;
    if (want == 0 || l->fp == NULL) {
        return 0;
    }

    FILE *f = fopen(l->path, "r");
    if (f == NULL) {
        return 0;
    }

    /* Pasada 1: contar líneas. */
    size_t total = 0;
    char   buf[ACCESS_LOG_LINE_MAX];
    while (fgets(buf, sizeof(buf), f) != NULL) {
        total++;
    }

    size_t avail = want < total ? want : total;
    size_t skip  = total - avail;

    /* Pasada 2: saltear las más viejas y copiar las últimas `avail` en orden
     * cronológico (más viejo -> más nuevo). */
    rewind(f);
    for (size_t i = 0; i < skip; i++) {
        if (fgets(buf, sizeof(buf), f) == NULL) {
            break;
        }
    }
    for (size_t i = 0; i < avail; i++) {
        if (fgets(lines[i], ACCESS_LOG_LINE_MAX, f) == NULL) {
            avail = i;
            break;
        }
        strip_newline(lines[i]);
    }
    fclose(f);

    /* Invertir para dejar la más reciente primero. */
    for (size_t i = 0; i < avail / 2; i++) {
        char tmp[ACCESS_LOG_LINE_MAX];
        memcpy(tmp, lines[i], ACCESS_LOG_LINE_MAX);
        memcpy(lines[i], lines[avail - 1 - i], ACCESS_LOG_LINE_MAX);
        memcpy(lines[avail - 1 - i], tmp, ACCESS_LOG_LINE_MAX);
    }
    return avail;
}
