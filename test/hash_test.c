#include <check.h>

#include "hashtable.h"

START_TEST(test_ht_init_success) {
  hash_table_t table;
  int result = ht_init(&table, NULL, 16, sizeof(int), sizeof(int));
  ck_assert_int_eq(result, HT_SUCCESS);
  ck_assert_ptr_nonnull(table.nodes);
  ck_assert_int_eq(table.size, 0);
  ck_assert_int_eq(table.capacity, 16);
}
END_TEST

START_TEST(test_ht_insert_and_lookup) {
  hash_table_t table;
  int key = 42;
  int value = 99;

  ht_init(&table, NULL, 16, sizeof(int), sizeof(int));
  ht_insert(&table, &key, &value);

  int *found_value = ht_lookup(&table, &key);
  ck_assert_ptr_nonnull(found_value);
  ck_assert_int_eq(*found_value, value);

  ht_destroy(&table);
}
END_TEST

START_TEST(test_ht_contain) {
  hash_table_t table;
  int key1 = 1;
  int value1 = 100;
  int key2 = 2;

  ht_init(&table, NULL, 16, sizeof(int), sizeof(int));
  ht_insert(&table, &key1, &value1);

  ck_assert_int_eq(ht_contain(&table, &key1), 1);
  ck_assert_int_eq(ht_contain(&table, &key2), 0);

  ht_destroy(&table);
}
END_TEST

START_TEST(test_ht_insert_overwrite) {
  hash_table_t table;
  int key = 5;
  int val1 = 10, val2 = 20;

  ht_init(&table, NULL, 16, sizeof(int), sizeof(int));
  ht_insert(&table, &key, &val1);
  ht_insert(&table, &key, &val2);  // overwrite

  int *value = ht_lookup(&table, &key);
  ck_assert_ptr_nonnull(value);
  ck_assert_int_eq(*value, val2);

  ht_destroy(&table);
}
END_TEST

Suite *hashtable_suite(void) {
  Suite *s = suite_create("HashTable");
  TCase *tc_core = tcase_create("Core");

  tcase_add_test(tc_core, test_ht_init_success);
  tcase_add_test(tc_core, test_ht_insert_and_lookup);
  tcase_add_test(tc_core, test_ht_contain);
  tcase_add_test(tc_core, test_ht_insert_overwrite);

  suite_add_tcase(s, tc_core);
  return s;
}

int main(void) {
  int number_failed;
  Suite *s = hashtable_suite();
  SRunner *sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? 0 : 1;
}