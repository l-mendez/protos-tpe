#ifndef SMCP_CLIENT_H_management_client_protocol
#define SMCP_CLIENT_H_management_client_protocol

#include <stdbool.h>
#include <stdio.h>

#define SMCP_TOKEN_MAX 256
#define SMCP_LINE_MAX 4096

typedef enum {
    SMCP_RESULT_OK,
    SMCP_RESULT_REJECTED,
    SMCP_RESULT_TRANSPORT_ERROR,
} smcp_result;

int
smcp_connect(const char *host, unsigned short port, FILE *err);

bool
smcp_is_token(const char *s);

bool
smcp_parse_count_status(const char *line, unsigned long *out);

smcp_result
smcp_cmd_auth(int fd, const char *user, const char *pass, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_metrics(int fd, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_list_users(int fd, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_add_user(int fd, const char *user, const char *pass, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_del_user(int fd, const char *user, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_get_config(int fd, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_set(int fd, const char *key, const char *value, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_log(int fd, const char *count, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_passwd(int fd, const char *pass, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_help(int fd, bool verbose, FILE *out, FILE *err);

smcp_result
smcp_cmd_quit(int fd, bool verbose, FILE *out, FILE *err);

#endif
