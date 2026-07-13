#include <stdlib.h>
#include <unistd.h>

#include <check.h>

#define main client_main_entry
#include "../src/client/main.c"
#undef main
#include "../src/client/smcp_client.c"

START_TEST(test_read_menu_choice_maps_eof_to_quit)
{
    FILE *empty = tmpfile();
    ck_assert_ptr_nonnull(empty);
    int saved_stdin = dup(STDIN_FILENO);
    ck_assert_int_ge(saved_stdin, 0);
    ck_assert_int_eq(STDIN_FILENO, dup2(fileno(empty), STDIN_FILENO));
    clearerr(stdin);

    int choice = 0;
    bool read_ok = read_menu_choice(&choice);

    ck_assert_int_eq(STDIN_FILENO, dup2(saved_stdin, STDIN_FILENO));
    close(saved_stdin);
    fclose(empty);
    clearerr(stdin);

    ck_assert(read_ok);
    ck_assert_int_eq('q', choice);
}
END_TEST

START_TEST(test_read_prompt_accepts_final_line_without_newline)
{
    FILE *input = tmpfile();
    ck_assert_ptr_nonnull(input);
    ck_assert_int_ge(fputs("1234567890123456789012345678901", input), 0);
    rewind(input);

    int saved_stdin = dup(STDIN_FILENO);
    ck_assert_int_ge(saved_stdin, 0);
    ck_assert_int_eq(STDIN_FILENO, dup2(fileno(input), STDIN_FILENO));
    clearerr(stdin);

    char value[32];
    bool read_ok = read_prompt("", value, sizeof(value), true);

    ck_assert_int_eq(STDIN_FILENO, dup2(saved_stdin, STDIN_FILENO));
    close(saved_stdin);
    fclose(input);
    clearerr(stdin);

    ck_assert(read_ok);
    ck_assert_str_eq("1234567890123456789012345678901", value);
}
END_TEST

START_TEST(test_read_prompt_accepts_max_length_line_with_newline)
{
    FILE *input = tmpfile();
    ck_assert_ptr_nonnull(input);
    ck_assert_int_ge(fputs("1234567890123456789012345678901\n", input), 0);
    rewind(input);

    int saved_stdin = dup(STDIN_FILENO);
    ck_assert_int_ge(saved_stdin, 0);
    ck_assert_int_eq(STDIN_FILENO, dup2(fileno(input), STDIN_FILENO));
    clearerr(stdin);

    char value[32];
    bool read_ok = read_prompt("", value, sizeof(value), true);

    ck_assert_int_eq(STDIN_FILENO, dup2(saved_stdin, STDIN_FILENO));
    close(saved_stdin);
    fclose(input);
    clearerr(stdin);

    ck_assert(read_ok);
    ck_assert_str_eq("1234567890123456789012345678901", value);
}
END_TEST

START_TEST(test_eof_quit_ends_session_when_server_rejects_it)
{
    ck_assert(should_end_session('q', SMCP_RESULT_REJECTED, true));
    ck_assert(!should_end_session('q', SMCP_RESULT_REJECTED, false));
    ck_assert(!should_end_session('q', SMCP_RESULT_TRANSPORT_ERROR, true));
}
END_TEST

static Suite *client_main_suite(void)
{
    Suite *s = suite_create("client_main");
    TCase *tc = tcase_create("input");
    tcase_add_test(tc, test_read_menu_choice_maps_eof_to_quit);
    tcase_add_test(tc, test_read_prompt_accepts_final_line_without_newline);
    tcase_add_test(tc, test_read_prompt_accepts_max_length_line_with_newline);
    tcase_add_test(tc, test_eof_quit_ends_session_when_server_rejects_it);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(client_main_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
