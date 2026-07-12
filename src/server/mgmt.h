#ifndef MGMT_H_smcp_dispatch
#define MGMT_H_smcp_dispatch

#include <stdbool.h>

#include "access_log.h"
#include "buffer.h"
#include "config.h"
#include "metrics.h"
#include "selector.h"
#include "users.h"

/**
 * mgmt.c -- núcleo del protocolo de monitoreo (SMCP): credenciales de admin y
 * despacho de comandos. Esta parte es independiente de sockets: convierte una
 * línea de comando en una respuesta escrita a un buffer, para poder testearla
 * sin red. El pegamento con el selector (accept/read/write) vive aparte.
 */

#define MGMT_LOG_MAX_LINES 50 /* tope de líneas que devuelve LOG (acota memoria) */

/* Credenciales del administrador: dueñas de los datos (mutable por PASSWD). */
struct AdminCreds {
    char name[256];
    char pass[256];
};

/** Inicializa las credenciales (name/pass NULL se tratan como vacíos). */
void
admin_init(struct AdminCreds *a, const char *name, const char *pass);

/** true si (name,pass) coinciden. Si no hay admin configurado, siempre false. */
bool
admin_check(const struct AdminCreds *a, const char *name, const char *pass);

/** Cambia la contraseña. false si es vacía o demasiado larga. */
bool
admin_set_pass(struct AdminCreds *a, const char *pass);

/* Recursos compartidos que SMCP lee/modifica (viven en main()). */
struct mgmt_deps {
    struct Users      *users;
    struct Metrics    *metrics;
    struct Config     *config;
    struct AccessLog  *access_log;
    struct AdminCreds *admin;
};

/* Estado por sesión SMCP. */
struct mgmt_session {
    const struct mgmt_deps *deps;
    bool authenticated;
};

void
mgmt_session_init(struct mgmt_session *s, const struct mgmt_deps *deps);

/**
 * Procesa una línea de comando y escribe la respuesta en `out`. `line` se
 * modifica in situ (tokenización). Devuelve true si la sesión debe cerrarse tras
 * drenar la respuesta (comando QUIT).
 */
bool
mgmt_handle_line(struct mgmt_session *s, char *line, buffer *out);

/** Inyecta los recursos compartidos usados por las sesiones SMCP. */
void
mgmt_set_deps(const struct mgmt_deps *deps);

/** Handler de accept para el socket pasivo de management. */
void
mgmt_passive_accept(struct selector_key *key);

/** Cantidad de conexiones SMCP activas, usada para el drenado al apagar. */
size_t
mgmt_active_connections(void);

#endif
