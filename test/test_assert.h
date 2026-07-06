#ifndef TEST_ASSERT_H
#define TEST_ASSERT_H

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define assert_int_eq(a, b) assert((a) == (b))
#define assert_int_ne(a, b) assert((a) != (b))
#define assert_int_ge(a, b) assert((a) >= (b))
#define assert_int_gt(a, b) assert((a) > (b))
#define assert_int_lt(a, b) assert((a) < (b))
#define assert_uint_eq(a, b) assert((a) == (b))
#define assert_uint_ne(a, b) assert((a) != (b))
#define assert_uint_ge(a, b) assert((a) >= (b))
#define assert_ptr_eq(a, b) assert((a) == (b))
#define assert_ptr_ne(a, b) assert((a) != (b))
#define assert_ptr_null(a) assert((a) == NULL)
#define assert_ptr_nonnull(a) assert((a) != NULL)
#define assert_str_eq(a, b) assert(strcmp((a), (b)) == 0)
#define assert_str_ne(a, b) assert(strcmp((a), (b)) != 0)

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
