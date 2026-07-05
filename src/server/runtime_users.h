#ifndef RUNTIME_USERS_H_socks5_runtime_users
#define RUNTIME_USERS_H_socks5_runtime_users

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "args.h"

typedef enum {
    RUNTIME_USER_OK = 0,
    RUNTIME_USER_INVALID,
    RUNTIME_USER_EXISTS,
    RUNTIME_USER_NOT_FOUND,
    RUNTIME_USER_FULL,
} runtime_user_result;

void
runtime_users_clear(void);

void
runtime_users_init_from_args(const struct users users[MAX_USERS]);

bool
runtime_users_auth_required(void);

size_t
runtime_users_count(void);

bool
runtime_users_validate(const uint8_t *user, size_t ulen,
                       const uint8_t *pass, size_t plen,
                       char *matched_user, size_t matched_cap);

runtime_user_result
runtime_users_add(const char *name, const char *pass);

runtime_user_result
runtime_users_del(const char *name);

runtime_user_result
runtime_users_passwd(const char *name, const char *pass);

bool
runtime_users_format_list(char *dst, size_t cap);

#endif
