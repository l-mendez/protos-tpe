#ifndef TEST_ASSERT_H
#define TEST_ASSERT_H

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Operands are evaluated into locals before the comparison so that any
 * function calls run unconditionally, even under -DNDEBUG where assert()
 * expands to nothing. This also keeps calls out of assert() itself, which
 * cppcheck flags as assertWithSideEffect.
 */
#define assert_cmp(a, op, b)          \
    do {                              \
        __typeof__(a) _a = (a);       \
        __typeof__(b) _b = (b);       \
        assert(_a op _b);             \
    } while (0)

#define assert_int_eq(a, b) assert_cmp(a, ==, b)
#define assert_int_ne(a, b) assert_cmp(a, !=, b)
#define assert_int_ge(a, b) assert_cmp(a, >=, b)
#define assert_int_gt(a, b) assert_cmp(a, >, b)
#define assert_int_lt(a, b) assert_cmp(a, <, b)
#define assert_uint_eq(a, b) assert_cmp(a, ==, b)
#define assert_uint_ne(a, b) assert_cmp(a, !=, b)
#define assert_uint_ge(a, b) assert_cmp(a, >=, b)
#define assert_ptr_eq(a, b) assert_cmp(a, ==, b)
#define assert_ptr_ne(a, b) assert_cmp(a, !=, b)
#define assert_ptr_null(a)              \
    do {                                \
        __typeof__(a) _a = (a);         \
        assert(_a == NULL);             \
    } while (0)
#define assert_ptr_nonnull(a)           \
    do {                                \
        __typeof__(a) _a = (a);         \
        assert(_a != NULL);             \
    } while (0)
#define assert_str_eq(a, b)             \
    do {                                \
        const char *_a = (a);           \
        const char *_b = (b);           \
        assert(strcmp(_a, _b) == 0);    \
    } while (0)
#define assert_str_ne(a, b)             \
    do {                                \
        const char *_a = (a);           \
        const char *_b = (b);           \
        assert(strcmp(_a, _b) != 0);    \
    } while (0)
#define assert_true(a)                  \
    do {                                \
        __typeof__(a) _a = (a);         \
        assert(_a);                     \
    } while (0)
#define assert_false(a)                 \
    do {                                \
        __typeof__(a) _a = (a);         \
        assert(!_a);                    \
    } while (0)

static int
test_run_case(void (*test)(void), const char *name)
{
    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        test();
        _exit(EXIT_SUCCESS);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        assert(errno == EINTR);
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
        return 0;
    }
    fprintf(stderr, "%s failed\n", name);
    return 1;
}

#endif
