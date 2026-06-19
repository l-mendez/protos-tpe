#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "echo.h"

#define ECHO_BUFFER_SIZE 4096

/* Linux evita el SIGPIPE en send() con esta flag; macOS no la define y lo
 * resuelve ignorando SIGPIPE en el arranque, así que aquí degrada a 0. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* En un socket no bloqueante, recv/send pueden devolver -1 con uno de estos
 * errno: no es un fallo de la conexión, hay que reintentar más tarde. */
static inline int
would_block(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

/** Estado por conexión: un único buffer por el que se streamea lo recibido. */
struct echo_conn {
    struct buffer buffer;
    uint8_t       raw[ECHO_BUFFER_SIZE];
};

static void
echo_read(struct selector_key *key)
{
    struct echo_conn *conn = key->data;

    size_t   space;
    uint8_t *ptr = buffer_write_ptr(&conn->buffer, &space);
    ssize_t  n   = recv(key->fd, ptr, space, 0);

    if (n > 0) {
        buffer_write_adv(&conn->buffer, n);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    /* n < 0 con would_block: reintentar luego, sin tocar la conexión.
     * n == 0 (cierre ordenado del par) o error real: desregistrar. */
    if (n < 0 && would_block(errno)) {
        return;
    }
    selector_unregister_fd(key->s, key->fd);
}

static void
echo_write(struct selector_key *key)
{
    struct echo_conn *conn = key->data;

    size_t   pending;
    uint8_t *ptr = buffer_read_ptr(&conn->buffer, &pending);
    ssize_t  n   = send(key->fd, ptr, pending, MSG_NOSIGNAL);

    if (n < 0) {
        /* buffer de envío lleno: mantener OP_WRITE y reintentar luego. */
        if (would_block(errno)) {
            return;
        }
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_read_adv(&conn->buffer, n);
    if (!buffer_can_read(&conn->buffer)) {
        selector_set_interest_key(key, OP_READ);
    }
}

static void
echo_close(struct selector_key *key)
{
    free(key->data);
    close(key->fd);
}

static const fd_handler echo_handler = {
    .handle_read  = echo_read,
    .handle_write = echo_write,
    .handle_close = echo_close,
};

void
echo_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage from;
    socklen_t               from_len = sizeof(from);

    int client = accept(key->fd, (struct sockaddr *)&from, &from_len);
    if (client < 0) {
        return;
    }

    if (selector_fd_set_nio(client) < 0) {
        close(client);
        return;
    }

    struct echo_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        close(client);
        return;
    }
    buffer_init(&conn->buffer, sizeof(conn->raw), conn->raw);

    if (selector_register(key->s, client, &echo_handler, OP_READ, conn) != SELECTOR_SUCCESS) {
        free(conn);
        close(client);
    }
}
