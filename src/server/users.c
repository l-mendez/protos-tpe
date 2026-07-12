#include <string.h>

#include "users.h"

void
users_init(struct Users *s)
{
    s->count = 0;
}

/* Índice del usuario con ese nombre, o -1 si no está. */
static int
users_find(const struct Users *s, const char *name)
{
    for (size_t i = 0; i < s->count; i++) {
        if (strcmp(s->entries[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

bool
users_add(struct Users *s, const char *name, const char *pass)
{
    if (name == NULL || pass == NULL) {
        return false;
    }
    const size_t nlen = strlen(name);
    const size_t plen = strlen(pass);
    if (nlen == 0 || plen == 0 ||
        nlen > USERS_NAME_MAX || plen > USERS_PASS_MAX) {
        return false;
    }
    if (s->count >= USERS_MAX) {
        return false;
    }
    if (users_find(s, name) >= 0) {
        return false;
    }
    memcpy(s->entries[s->count].name, name, nlen + 1);
    memcpy(s->entries[s->count].pass, pass, plen + 1);
    s->count++;
    return true;
}

bool
users_del(struct Users *s, const char *name)
{
    const int idx = users_find(s, name);
    if (idx < 0) {
        return false;
    }
    /* Compacta desplazando los posteriores: preserva el orden de alta. */
    for (size_t i = (size_t)idx; i + 1 < s->count; i++) {
        s->entries[i] = s->entries[i + 1];
    }
    s->count--;
    return true;
}

bool
users_exists(const struct Users *s, const char *name)
{
    return users_find(s, name) >= 0;
}

bool
users_validate(const struct Users *s,
               const uint8_t *user, size_t ulen,
               const uint8_t *pass, size_t plen)
{
    if (ulen == 0 || plen == 0) {
        return false;
    }
    for (size_t i = 0; i < s->count; i++) {
        const char *n = s->entries[i].name;
        const char *p = s->entries[i].pass;
        if (strlen(n) == ulen && memcmp(n, user, ulen) == 0) {
            return strlen(p) == plen && memcmp(p, pass, plen) == 0;
        }
    }
    return false;
}

size_t
users_count(const struct Users *s)
{
    return s->count;
}

const char *
users_name_at(const struct Users *s, size_t i)
{
    if (i >= s->count) {
        return NULL;
    }
    return s->entries[i].name;
}
