#include "runtime_users.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

struct runtime_user {
    char name[256];
    char pass[256];
};

static struct runtime_user users_store[MAX_USERS];
static size_t user_count = 0;

static bool valid_token(const char *s)
{
    size_t len;

    if (s == NULL) {
        return false;
    }
    len = strlen(s);
    if (len == 0 || len > 255) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isspace(c) || c < 0x21 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

static int find_user(const char *name)
{
    for (size_t i = 0; i < user_count; i++) {
        if (strcmp(users_store[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

void runtime_users_clear(void)
{
    memset(users_store, 0, sizeof(users_store));
    user_count = 0;
}

void runtime_users_init_from_args(const struct users users[MAX_USERS])
{
    runtime_users_clear();
    if (users == NULL) {
        return;
    }
    for (int i = 0; i < MAX_USERS && users[i].name != NULL; i++) {
        (void)runtime_users_add(users[i].name, users[i].pass);
    }
}

bool runtime_users_auth_required(void)
{
    return user_count > 0;
}

size_t runtime_users_count(void)
{
    return user_count;
}

bool runtime_users_validate(const uint8_t *user, size_t ulen,
                            const uint8_t *pass, size_t plen,
                            char *matched_user, size_t matched_cap)
{
    if (user == NULL || pass == NULL || ulen == 0 || plen == 0) {
        return false;
    }
    for (size_t i = 0; i < user_count; i++) {
        const char *name = users_store[i].name;
        const char *pw = users_store[i].pass;
        if (strlen(name) == ulen && memcmp(name, user, ulen) == 0 &&
            strlen(pw) == plen && memcmp(pw, pass, plen) == 0) {
            if (matched_user != NULL && matched_cap > 0) {
                snprintf(matched_user, matched_cap, "%s", name);
            }
            return true;
        }
    }
    return false;
}

runtime_user_result runtime_users_add(const char *name, const char *pass)
{
    if (!valid_token(name) || !valid_token(pass)) {
        return RUNTIME_USER_INVALID;
    }
    if (find_user(name) >= 0) {
        return RUNTIME_USER_EXISTS;
    }
    if (user_count >= MAX_USERS) {
        return RUNTIME_USER_FULL;
    }
    snprintf(users_store[user_count].name, sizeof(users_store[user_count].name), "%s", name);
    snprintf(users_store[user_count].pass, sizeof(users_store[user_count].pass), "%s", pass);
    user_count++;
    return RUNTIME_USER_OK;
}

runtime_user_result runtime_users_del(const char *name)
{
    int idx;

    if (!valid_token(name)) {
        return RUNTIME_USER_INVALID;
    }
    idx = find_user(name);
    if (idx < 0) {
        return RUNTIME_USER_NOT_FOUND;
    }
    for (size_t i = (size_t)idx; i + 1 < user_count; i++) {
        users_store[i] = users_store[i + 1];
    }
    user_count--;
    memset(&users_store[user_count], 0, sizeof(users_store[user_count]));
    return RUNTIME_USER_OK;
}

runtime_user_result runtime_users_passwd(const char *name, const char *pass)
{
    int idx;

    if (!valid_token(name) || !valid_token(pass)) {
        return RUNTIME_USER_INVALID;
    }
    idx = find_user(name);
    if (idx < 0) {
        return RUNTIME_USER_NOT_FOUND;
    }
    snprintf(users_store[idx].pass, sizeof(users_store[idx].pass), "%s", pass);
    return RUNTIME_USER_OK;
}

bool runtime_users_format_list(char *dst, size_t cap)
{
    size_t used = 0;

    if (dst == NULL || cap == 0) {
        return false;
    }
    dst[0] = '\0';
    for (size_t i = 0; i < user_count; i++) {
        int written = snprintf(dst + used, cap - used, "%s%s",
                               i == 0 ? "" : " ", users_store[i].name);
        if (written < 0 || (size_t)written >= cap - used) {
            dst[0] = '\0';
            return false;
        }
        used += (size_t)written;
    }
    return true;
}
