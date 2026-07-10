#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

/* users vive en src/server, fuera del archivo compartido contra el que linkean
 * los tests, así que se incluye la unidad directamente (mismo enfoque que
 * metrics_test / auth_test). Cada caso usa su propia instancia. */
#include "../src/server/users.c"

/* Helper: valida credenciales pasadas como C-strings. */
static bool validate_str(const struct Users *s, const char *user, const char *pass)
{
    return users_validate(s, (const uint8_t *)user, strlen(user),
                          (const uint8_t *)pass, strlen(pass));
}

START_TEST(test_users_empty)
{
    struct Users s;
    users_init(&s);

    ck_assert_uint_eq(0, users_count(&s));
    ck_assert(!validate_str(&s, "alan", "pwd"));
    ck_assert_ptr_null(users_name_at(&s, 0));
}
END_TEST

START_TEST(test_users_add_and_validate)
{
    struct Users s;
    users_init(&s);

    ck_assert(users_add(&s, "alan", "pwd"));
    ck_assert_uint_eq(1, users_count(&s));

    ck_assert(validate_str(&s, "alan", "pwd"));   /* correctas */
    ck_assert(!validate_str(&s, "alan", "nope")); /* pass incorrecta */
    ck_assert(!validate_str(&s, "juana", "pwd")); /* usuario inexistente */
}
END_TEST

START_TEST(test_users_add_duplicate)
{
    struct Users s;
    users_init(&s);

    ck_assert(users_add(&s, "alan", "pwd"));
    ck_assert(!users_add(&s, "alan", "otra")); /* nombre ya existe */
    ck_assert_uint_eq(1, users_count(&s));
    ck_assert(validate_str(&s, "alan", "pwd")); /* la original no cambió */
}
END_TEST

START_TEST(test_users_add_invalid)
{
    struct Users s;
    users_init(&s);

    ck_assert(!users_add(&s, "", "pwd"));  /* nombre vacío */
    ck_assert(!users_add(&s, "alan", "")); /* pass vacía */

    char longname[USERS_NAME_MAX + 2];
    memset(longname, 'x', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    ck_assert(!users_add(&s, longname, "pwd")); /* nombre demasiado largo */

    ck_assert_uint_eq(0, users_count(&s)); /* ninguna alta prosperó */
}
END_TEST

START_TEST(test_users_add_full)
{
    struct Users s;
    users_init(&s);

    char name[32];
    for (int i = 0; i < USERS_MAX; i++) {
        snprintf(name, sizeof(name), "user%d", i);
        ck_assert(users_add(&s, name, "pwd"));
    }
    ck_assert_uint_eq(USERS_MAX, users_count(&s));

    ck_assert(!users_add(&s, "unomas", "pwd")); /* almacén lleno */
    ck_assert_uint_eq(USERS_MAX, users_count(&s));
}
END_TEST

START_TEST(test_users_del)
{
    struct Users s;
    users_init(&s);

    ck_assert(users_add(&s, "alan", "pwd"));
    ck_assert(users_del(&s, "alan"));
    ck_assert_uint_eq(0, users_count(&s));
    ck_assert(!validate_str(&s, "alan", "pwd")); /* ya no valida */

    ck_assert(!users_del(&s, "alan")); /* borrar inexistente */
}
END_TEST

START_TEST(test_users_del_compacts_in_order)
{
    struct Users s;
    users_init(&s);

    ck_assert(users_add(&s, "a", "1"));
    ck_assert(users_add(&s, "b", "2"));
    ck_assert(users_add(&s, "c", "3"));

    ck_assert(users_del(&s, "b")); /* del del medio */
    ck_assert_uint_eq(2, users_count(&s));

    /* orden estable: quedan a, c */
    ck_assert_str_eq("a", users_name_at(&s, 0));
    ck_assert_str_eq("c", users_name_at(&s, 1));
    ck_assert_ptr_null(users_name_at(&s, 2));
}
END_TEST

START_TEST(test_users_validate_length_exact)
{
    struct Users s;
    users_init(&s);
    ck_assert(users_add(&s, "alan", "pwd"));

    /* prefijo del nombre almacenado no debe validar (longitud exacta) */
    ck_assert(!users_validate(&s, (const uint8_t *)"ala", 3,
                              (const uint8_t *)"pwd", 3));
    /* nombre con sufijo extra tampoco */
    ck_assert(!users_validate(&s, (const uint8_t *)"alanx", 5,
                              (const uint8_t *)"pwd", 3));
    /* credenciales vacías se rechazan */
    ck_assert(!users_validate(&s, (const uint8_t *)"", 0,
                              (const uint8_t *)"pwd", 3));
    ck_assert(!users_validate(&s, (const uint8_t *)"alan", 4,
                              (const uint8_t *)"", 0));
}
END_TEST

Suite *suite(void)
{
    Suite *s  = suite_create("users");
    TCase *tc = tcase_create("users");

    tcase_add_test(tc, test_users_empty);
    tcase_add_test(tc, test_users_add_and_validate);
    tcase_add_test(tc, test_users_add_duplicate);
    tcase_add_test(tc, test_users_add_invalid);
    tcase_add_test(tc, test_users_add_full);
    tcase_add_test(tc, test_users_del);
    tcase_add_test(tc, test_users_del_compacts_in_order);
    tcase_add_test(tc, test_users_validate_length_exact);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(suite());
    int      number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
