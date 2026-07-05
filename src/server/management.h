#ifndef MANAGEMENT_H_socks5_management
#define MANAGEMENT_H_socks5_management

#include <stddef.h>

#include "selector.h"

#define MANAGEMENT_LINE_MAX 1024
#define MANAGEMENT_RESPONSE_MAX 4096

void
management_set_admin(const char *name, const char *pass);

void
management_dispatch_line(const char *line, char *out, size_t cap);

void
management_passive_accept(struct selector_key *key);

size_t
management_active_connections(void);

#endif
