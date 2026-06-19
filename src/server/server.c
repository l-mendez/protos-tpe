#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server.h"

int
server_setup_passive(const char *addr, unsigned short port)
{
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%hu", port);

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags    = AI_PASSIVE | AI_NUMERICSERV,
    };

    struct addrinfo *list;
    if (getaddrinfo(addr, port_str, &hints, &list) != 0) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = list; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        /* SO_REUSEADDR es deseable pero no crítico: si falla, igual se intenta
         * el bind, así que se descarta el resultado a propósito. */
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 20) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(list);
    return fd;
}
