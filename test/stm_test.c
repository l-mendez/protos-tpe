#include <stdlib.h>
#include <stdbool.h>
#include "test_assert.h"
#include "selector.h"
#include "stm.h"

enum test_states {
    A,
    B,
    C,
};

struct data {
    bool arrived  [3];
    bool departed[3];
    unsigned i;
};

static void
on_arrival(const unsigned state, struct selector_key *key) {
    struct data *d = (struct data *)key->data;
    d->arrived[state] = true;
}

static void
on_departure(const unsigned state,struct selector_key *key) {
    struct data *d = (struct data *)key->data;
    d->departed[state] = true;
}

static unsigned
on_read_ready(struct selector_key *key) {
    struct data *d = (struct data *)key->data;
    unsigned ret;

    if(d->i < C) {
        ret = ++d->i;
    } else {
        ret = C;
    }
    return ret;
}

static unsigned
on_write_ready(struct selector_key *key) {
    return on_read_ready(key);
}

static const struct state_definition statbl[] = {
    {
        .state          = A,
        .on_arrival     = on_arrival,
        .on_departure   = on_departure,
        .on_read_ready  = on_read_ready,
        .on_write_ready = on_write_ready,
    },{
        .state          = B,
        .on_arrival     = on_arrival,
        .on_departure   = on_departure,
        .on_read_ready  = on_read_ready,
        .on_write_ready = on_write_ready,
    },{
        .state          = C,
        .on_arrival     = on_arrival,
        .on_departure   = on_departure,
        .on_read_ready  = on_read_ready,
        .on_write_ready = on_write_ready,
    }
};

//static bool init = false;

START_TEST (test_buffer_misc) {
    struct state_machine stm = {
        .initial   = A,
        .max_state = C,
        .states    = statbl,
    };
    struct data data = {
        .i = 0,
    };
    struct selector_key  key = {
        .data = &data,
    };
    stm_init(&stm);
    ck_assert_uint_eq(A, stm_state(&stm));
    ck_assert_uint_eq(false,  data.arrived[A]);
    ck_assert_uint_eq(false,  data.arrived[B]);
    ck_assert_uint_eq(false,  data.arrived[C]);
    ck_assert_ptr_null(stm.current);

    stm_handler_read(&stm, &key);
    ck_assert_uint_eq(B,     stm_state(&stm));
    ck_assert_uint_eq(true,  data.arrived[A]);
    ck_assert_uint_eq(true,  data.arrived[B]);
    ck_assert_uint_eq(false, data.arrived[C]);
    ck_assert_uint_eq(true,  data.departed[A]);
    ck_assert_uint_eq(false, data.departed[B]);
    ck_assert_uint_eq(false, data.departed[C]);

    stm_handler_write(&stm, &key);
    ck_assert_uint_eq(C,     stm_state(&stm));
    ck_assert_uint_eq(true,  data.arrived[A]);
    ck_assert_uint_eq(true,  data.arrived[B]);
    ck_assert_uint_eq(true,  data.arrived[C]);
    ck_assert_uint_eq(true,  data.departed[A]);
    ck_assert_uint_eq(true,  data.departed[B]);
    ck_assert_uint_eq(false, data.departed[C]);

    stm_handler_read(&stm, &key);
    ck_assert_uint_eq(C,     stm_state(&stm));
    ck_assert_uint_eq(true,  data.arrived[A]);
    ck_assert_uint_eq(true,  data.arrived[B]);
    ck_assert_uint_eq(true,  data.arrived[C]);
    ck_assert_uint_eq(true,  data.departed[A]);
    ck_assert_uint_eq(true,  data.departed[B]);
    ck_assert_uint_eq(false, data.departed[C]);

    stm_handler_close(&stm, &key);
}
END_TEST

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_buffer_misc, "test_buffer_misc");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
