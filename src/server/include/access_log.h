#ifndef ACCESS_LOG_H_socks5_access_log
#define ACCESS_LOG_H_socks5_access_log

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/**
 * access_log.c -- registro de accesos persistente.
 *
 * Escribe una línea por intento de CONNECT en un archivo de texto en modo
 * *append* (fuente de verdad, durable: sobrevive reinicios). El comando LOG del
 * protocolo de monitoreo devuelve las últimas líneas vía access_log_tail().
 *
 * Formato de línea (ver protocolo.md §7):
 *   <timestamp ISO-8601 UTC> <usuario> CONNECT <host:puerto> <resultado>
 *
 * Estilo de instancia (como Metrics/Users): el llamador provee el almacenamiento.
 * Escribir a un archivo regular es compatible con el modelo no bloqueante (la
 * restricción aplica a sockets, no a archivos).
 */

#define ACCESS_LOG_LINE_MAX 1024 /* cota de una línea de registro */
#define ACCESS_LOG_PATH_MAX 4096

struct AccessLog {
    FILE *fp;                        /* handle de append; NULL si deshabilitado */
    char  path[ACCESS_LOG_PATH_MAX]; /* ruta, para reabrir en lectura en tail */
};

/**
 * Abre (o crea) el archivo de log en modo append. Devuelve false si no se pudo
 * abrir; en ese caso el registro queda deshabilitado (record/tail no-op).
 */
bool
access_log_open(struct AccessLog *l, const char *path);

/** Cierra el archivo si estaba abierto. */
void
access_log_close(struct AccessLog *l);

/**
 * Anexa un registro con la marca de tiempo actual (UTC). No-op si el log está
 * deshabilitado. `user` == "-" indica conexión anónima.
 */
void
access_log_record(struct AccessLog *l, const char *user,
                  const char *dest, const char *result);

/**
 * Copia las últimas `n` líneas (más reciente primero) en `lines`, cada una sin
 * el '\n' final. Escribe a lo sumo `cap` líneas. Devuelve la cantidad escrita.
 */
size_t
access_log_tail(const struct AccessLog *l, size_t n,
                char lines[][ACCESS_LOG_LINE_MAX], size_t cap);

#endif
