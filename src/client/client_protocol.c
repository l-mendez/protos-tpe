#include "client_protocol.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int token_valid(const char *s)
{
    size_t len;

    if (s == NULL) {
        return 0;
    }
    len = strlen(s);
    if (len == 0 || len > 255) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isspace(c) || c < 0x21 || c > 0x7e) {
            return 0;
        }
    }
    return 1;
}

static client_cmd_result write_command(char *out, size_t cap, const char *fmt,
                                       const char *a, const char *b,
                                       const char *c)
{
    int written;

    if (out == NULL || cap == 0) {
        return CLIENT_CMD_TOO_LONG;
    }
    if (a == NULL) {
        written = snprintf(out, cap, "%s", fmt);
    } else if (b == NULL) {
        written = snprintf(out, cap, fmt, a);
    } else if (c == NULL) {
        written = snprintf(out, cap, fmt, a, b);
    } else {
        written = snprintf(out, cap, fmt, a, b, c);
    }
    if (written < 0 || (size_t)written >= cap) {
        out[0] = '\0';
        return CLIENT_CMD_TOO_LONG;
    }
    return CLIENT_CMD_OK;
}

client_cmd_result client_build_command(int argc, char **argv, char *out, size_t cap)
{
    if (argc == 1 && strcmp(argv[0], "metrics") == 0) {
        return write_command(out, cap, "METRICS", NULL, NULL, NULL);
    }
    if (argc >= 2 && strcmp(argv[0], "users") == 0) {
        if (strcmp(argv[1], "list") == 0 && argc == 2) {
            return write_command(out, cap, "USERS LIST", NULL, NULL, NULL);
        }
        if (strcmp(argv[1], "add") == 0 && argc == 4 &&
            token_valid(argv[2]) && token_valid(argv[3])) {
            return write_command(out, cap, "USERS ADD %s %s", argv[2], argv[3], NULL);
        }
        if (strcmp(argv[1], "del") == 0 && argc == 3 && token_valid(argv[2])) {
            return write_command(out, cap, "USERS DEL %s", argv[2], NULL, NULL);
        }
        if (strcmp(argv[1], "passwd") == 0 && argc == 4 &&
            token_valid(argv[2]) && token_valid(argv[3])) {
            return write_command(out, cap, "USERS PASSWD %s %s", argv[2], argv[3], NULL);
        }
        return CLIENT_CMD_USAGE;
    }
    if (argc >= 2 && strcmp(argv[0], "config") == 0) {
        if (strcmp(argv[1], "list") == 0 && argc == 2) {
            return write_command(out, cap, "CONFIG LIST", NULL, NULL, NULL);
        }
        if (strcmp(argv[1], "get") == 0 && argc == 3 && token_valid(argv[2])) {
            return write_command(out, cap, "CONFIG GET %s", argv[2], NULL, NULL);
        }
        if (strcmp(argv[1], "set") == 0 && argc == 4 &&
            token_valid(argv[2]) && token_valid(argv[3])) {
            return write_command(out, cap, "CONFIG SET %s %s", argv[2], argv[3], NULL);
        }
        return CLIENT_CMD_USAGE;
    }
    return CLIENT_CMD_USAGE;
}
