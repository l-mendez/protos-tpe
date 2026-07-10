#ifndef USERS_H_socks5_user_store
#define USERS_H_socks5_user_store

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * users.c -- almacén dinámico de usuarios del proxy (user/pass, RFC 1929).
 *
 * A diferencia de `struct User` (que apunta a memoria de argv), este almacén es
 * *dueño* de los datos: copia nombre y contraseña. Se siembra desde los usuarios
 * de línea de comandos al arrancar y luego el protocolo de monitoreo lo modifica
 * en caliente (ADD-USER / DEL-USER / LIST-USERS).
 *
 * Estilo de instancia (como Metrics/buffer): el llamador provee el almacenamiento
 * y lo pasa por puntero. Se accede sólo desde el hilo del selector.
 */

#define USERS_MAX      100 /* capacidad del almacén en runtime */
#define USERS_NAME_MAX 255 /* RFC 1929: ULEN cabe en 1 byte */
#define USERS_PASS_MAX 255 /* RFC 1929: PLEN cabe en 1 byte */

struct Users {
    size_t count;
    struct {
        char name[USERS_NAME_MAX + 1];
        char pass[USERS_PASS_MAX + 1];
    } entries[USERS_MAX];
};

/** Deja el almacén vacío. El llamador provee el almacenamiento. */
void
users_init(struct Users *s);

/**
 * Da de alta un usuario. Devuelve false si el nombre ya existe, si el almacén
 * está lleno, o si nombre/contraseña son vacíos o exceden el máximo.
 */
bool
users_add(struct Users *s, const char *name, const char *pass);

/** Elimina un usuario por nombre. Devuelve false si no existe. */
bool
users_del(struct Users *s, const char *name);

/**
 * Valida credenciales con longitudes explícitas (RFC 1929: pueden contener
 * cualquier byte). La comparación es exacta en longitud. Credenciales vacías
 * (ulen o plen == 0) se rechazan.
 */
bool
users_validate(const struct Users *s,
               const uint8_t *user, size_t ulen,
               const uint8_t *pass, size_t plen);

/** Cantidad de usuarios actualmente en el almacén. */
size_t
users_count(const struct Users *s);

/**
 * Nombre del i-ésimo usuario (para LIST-USERS), o NULL si i >= count. El orden
 * de alta es estable (DEL-USER compacta desplazando los posteriores).
 */
const char *
users_name_at(const struct Users *s, size_t i);

#endif
