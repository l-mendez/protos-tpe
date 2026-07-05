#ifndef CLIENT_PROTOCOL_H_socks5_management_client
#define CLIENT_PROTOCOL_H_socks5_management_client

#include <stddef.h>

typedef enum {
    CLIENT_CMD_OK = 0,
    CLIENT_CMD_USAGE,
    CLIENT_CMD_TOO_LONG,
} client_cmd_result;

client_cmd_result
client_build_command(int argc, char **argv, char *out, size_t cap);

#endif
