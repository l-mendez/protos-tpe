#include <stdlib.h>

#include <check.h>

#include "../src/server/config.c"

START_TEST(test_config_defaults)
{
    struct Config c;
    config_init(&c, 1024);

    ck_assert_uint_eq(CONFIG_CONN_TIMEOUT_DEFAULT, config_conn_timeout(&c));
    ck_assert_uint_eq(CONFIG_IO_BUFFER_SIZE_DEFAULT, config_io_buffer_size(&c));
    ck_assert_uint_eq(500, config_max_connections(&c)); /* deja fds para relay y control */
}
END_TEST

START_TEST(test_config_conn_timeout_range)
{
    struct Config c;
    config_init(&c, 1024);

    ck_assert(config_set_conn_timeout(&c, 30));
    ck_assert_uint_eq(30, config_conn_timeout(&c));

    ck_assert(config_set_conn_timeout(&c, CONFIG_CONN_TIMEOUT_MIN));
    ck_assert(config_set_conn_timeout(&c, CONFIG_CONN_TIMEOUT_MAX));

    /* fuera de rango: rechaza y deja el último valor válido (MAX) */
    ck_assert(!config_set_conn_timeout(&c, 0));
    ck_assert(!config_set_conn_timeout(&c, CONFIG_CONN_TIMEOUT_MAX + 1));
    ck_assert_uint_eq(CONFIG_CONN_TIMEOUT_MAX, config_conn_timeout(&c));
}
END_TEST

START_TEST(test_config_io_buffer_range)
{
    struct Config c;
    config_init(&c, 1024);

    ck_assert(config_set_io_buffer_size(&c, 16384));
    ck_assert_uint_eq(16384, config_io_buffer_size(&c));

    ck_assert(config_set_io_buffer_size(&c, CONFIG_IO_BUFFER_SIZE_MIN));
    ck_assert(config_set_io_buffer_size(&c, CONFIG_IO_BUFFER_SIZE_MAX));

    ck_assert(!config_set_io_buffer_size(&c, CONFIG_IO_BUFFER_SIZE_MIN - 1));
    ck_assert(!config_set_io_buffer_size(&c, CONFIG_IO_BUFFER_SIZE_MAX + 1));
    ck_assert_uint_eq(CONFIG_IO_BUFFER_SIZE_MAX, config_io_buffer_size(&c));
}
END_TEST

START_TEST(test_config_max_connections_range)
{
    struct Config c;
    config_init(&c, 1024);

    ck_assert(config_set_max_connections(&c, 400));
    ck_assert_uint_eq(400, config_max_connections(&c));

    ck_assert(config_set_max_connections(&c, 1));    /* mínimo */
    ck_assert(config_set_max_connections(&c, 500));  /* el techo exacto */

    ck_assert(!config_set_max_connections(&c, 0));    /* bajo el mínimo */
    ck_assert(!config_set_max_connections(&c, 501));  /* sobre el techo */
    ck_assert_uint_eq(500, config_max_connections(&c));
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("config");
    TCase *tc = tcase_create("config");

    tcase_add_test(tc, test_config_defaults);
    tcase_add_test(tc, test_config_conn_timeout_range);
    tcase_add_test(tc, test_config_io_buffer_range);
    tcase_add_test(tc, test_config_max_connections_range);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
