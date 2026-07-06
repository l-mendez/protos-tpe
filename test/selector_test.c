#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_assert.h"

#define INITIAL_SIZE ((size_t) 1024)

// para poder testear las funciones estaticas
#include "selector.c"

static void
test_selector_error(void)
{
    const selector_status data[] = {
        SELECTOR_SUCCESS,
        SELECTOR_ENOMEM,
        SELECTOR_MAXFD,
        SELECTOR_IARGS,
        SELECTOR_IO,
        SELECTOR_FDINUSE,
    };
    // verifica que `selector_error' tiene mensajes especificos
    for(unsigned i = 0 ; i < N(data); i++) {
        assert_str_ne(ERROR_DEFAULT_MSG, selector_error(data[i]));
    }
}

static void
test_next_capacity(void)
{
    const size_t data[] = {
         0,  1,
         1,  2,
         2,  4,
         3,  4,
         4,  8,
         7,  8,
         8, 16,
        15, 16,
        31, 32,
        16, 32,
        ITEMS_MAX_SIZE, ITEMS_MAX_SIZE,
        ITEMS_MAX_SIZE + 1, ITEMS_MAX_SIZE,
    };
    for(unsigned i = 0; i < N(data) / 2; i++ ) {
        assert_uint_eq(data[i * 2 + 1] + 1, next_capacity(data[i*2]));
    }
}

static void
test_ensure_capacity(void)
{
    fd_selector s = selector_new(0);
    for(size_t i = 0; i < s->fd_size; i++) {
        assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    size_t n = 1;
    assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    assert_uint_ge(s->fd_size, n);

    n = 10;
    assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    assert_uint_ge(s->fd_size, n);

    const size_t last_size = s->fd_size;
    n = ITEMS_MAX_SIZE + 1;
    assert_int_eq(SELECTOR_MAXFD, ensure_capacity(s, n));
    assert_uint_eq(last_size, s->fd_size);

    for(size_t i = 0; i < s->fd_size; i++) {
        assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    selector_destroy(s);

    assert_ptr_null(selector_new(ITEMS_MAX_SIZE + 1));
}

// callbacks de prueba
static void *data_mark = (void *)0x0FF1CE;
static unsigned destroy_count = 0;
static void
destroy_callback(struct selector_key *key) {
    assert_ptr_nonnull(key->s);
    assert_int_ge(key->fd, 0);
    assert_int_lt(key->fd, ITEMS_MAX_SIZE);

    assert_ptr_eq(data_mark, key->data);
    destroy_count++;
}

static void
test_selector_register_fd(void)
{
    destroy_count = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    assert_ptr_nonnull(s);

    assert_uint_eq(SELECTOR_IARGS,   selector_register(0, -1, 0, 0, data_mark));

    const struct fd_handler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    const struct item *item = s->fds + fd;
    assert_int_eq (fd,         s->max_fd);
    assert_int_eq (fd,         item->fd);
    assert_ptr_eq (&h,         item->handler);
    assert_uint_eq(0,          item->interest);
    assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    // destroy desregistró?
    assert_uint_eq(1,          destroy_count);

}

static void
test_selector_register_unregister_register(void)
{
    destroy_count = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    assert_ptr_nonnull(s);

    const struct fd_handler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    assert_uint_eq(SELECTOR_SUCCESS,
                      selector_unregister_fd(s, fd));

    const struct item *item = s->fds + fd;
    assert_int_eq (0,          s->max_fd);
    assert_int_eq (FD_UNUSED,  item->fd);
    assert_ptr_eq (0x00,       item->handler);
    assert_uint_eq(0,          item->interest);
    assert_ptr_eq (0x00,       item->data);

    assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    item = s->fds + fd;
    assert_int_eq (fd,         s->max_fd);
    assert_int_eq (fd,         item->fd);
    assert_ptr_eq (&h,         item->handler);
    assert_uint_eq(0,          item->interest);
    assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    assert_uint_eq(2,          destroy_count);

}

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_selector_error, "test_selector_error");
    failures += test_run_case(test_next_capacity, "test_next_capacity");
    failures += test_run_case(test_ensure_capacity, "test_ensure_capacity");
    failures += test_run_case(test_selector_register_fd, "test_selector_register_fd");
    failures += test_run_case(test_selector_register_unregister_register, "test_selector_register_unregister_register");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
