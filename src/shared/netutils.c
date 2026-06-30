#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr) {
    if(addr == 0) {
        strncpy(buff, "null", buffsize);
        return buff;
    }
    const uint8_t *p = 0x00;
    size_t addr_len = 0;
    uint16_t port = 0;
    bool handled = sockaddr_get_addr_port(addr, &p, &addr_len, &port);
    (void)addr_len;

    if(handled) {
        if (inet_ntop(addr->sa_family, p,  buff, buffsize) == 0) {
            strncpy(buff, "unknown ip", buffsize);
            buff[buffsize - 1] = 0;
        }
    } else {
        strncpy(buff, "unknown", buffsize);
    }

    strncat(buff, ":", buffsize);
    buff[buffsize - 1] = 0;
    const size_t len = strlen(buff);

    if(handled) {
        snprintf(buff + len, buffsize - len, "%u", port);
    }
    buff[buffsize - 1] = 0;

    return buff;
}

bool
sockaddr_get_addr_port(const struct sockaddr *sa, const uint8_t **addr,
                       size_t *addr_len, uint16_t *port) {
    if(sa == NULL || addr == NULL || addr_len == NULL || port == NULL) {
        return false;
    }

    switch(sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sa4 = (const struct sockaddr_in *)sa;
            *addr = (const uint8_t *)&sa4->sin_addr;
            *addr_len = 4;
            *port = ntohs(sa4->sin_port);
            return true;
        }
        case AF_INET6: {
            const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)sa;
            *addr = (const uint8_t *)&sa6->sin6_addr;
            *addr_len = 16;
            *port = ntohs(sa6->sin6_port);
            return true;
        }
        default:
            return false;
    }
}

int
sock_blocking_write(const int fd, buffer *b) {
        int  ret = 0;
    ssize_t  nwritten;
	 size_t  n;
	uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int
sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char* out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
    error:

    return ret;
}
