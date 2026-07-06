#include <stdio.h>
#include <stdlib.h>
#include "test_assert.h"

#include "parser_utils.h"

static void
assert_eq(const unsigned type, const int c, const struct parser_event *e) {
    ck_assert_ptr_eq (0,    e->next);
    ck_assert_uint_eq(1,    e->n);
    ck_assert_uint_eq(type, e->type);
    ck_assert_uint_eq(c,    e->data[0]);

}

START_TEST (test_eq) {
    const struct parser_definition d = parser_utils_strcmpi("foo");

    struct parser *parser = parser_init(parser_no_classes(), &d);
    assert_eq(STRING_CMP_MAYEQ,  'f', parser_feed(parser, 'f'));
    assert_eq(STRING_CMP_MAYEQ,  'O', parser_feed(parser, 'O'));
    assert_eq(STRING_CMP_EQ,     'o', parser_feed(parser, 'o'));
    assert_eq(STRING_CMP_NEQ,    'X', parser_feed(parser, 'X'));
    assert_eq(STRING_CMP_NEQ,    'y', parser_feed(parser, 'y'));

    parser_destroy(parser);
    parser_utils_strcmpi_destroy(&d);
}
END_TEST

int
main(void)
{
    int failures = 0;
    failures += test_run_case(test_eq, "test_eq");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
