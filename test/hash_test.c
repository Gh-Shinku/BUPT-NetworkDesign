#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"

static void test1() {
  hash_table_t *table = ht_init(NULL, NULL, 16, sizeof(int));
  int *k = (int *)malloc(sizeof(int)), *v = (int *)malloc(sizeof(int));
  *k = 5;
  *v = 6;
  // assert(ht_insert(table, k, v) == 0);
  assert(ht_contain(table, k) == 0);
  assert(*(int *)ht_lookup(table, k) == *v);
  assert(ht_free(table) == 0);
}

static void test2() {
  hash_table_t *table = ht_init(NULL, ht_str_comp, 16, STRING);
  const char *s = "www.baidu.com";
  const char *v = "192.168.1.1";
  char *ss = strdup(s);
  char *vv = strdup(v);
  // assert(ht_insert(table, ss, vv) == 0);
  assert(ht_contain(table, ss) == 0);
  assert(strcmp((char *)ht_lookup(table, ss), vv) == 0);
  assert(ht_free(table) == 0);
}

static void test_resize() {
  printf("Testing hash table resize...\n");
  hash_table_t *table = ht_init(NULL, NULL, 4, sizeof(int));

  for (int i = 0; i < 20; i++) {
    int *key = (int *)malloc(sizeof(int));
    int *value = (int *)malloc(sizeof(int));
    *key = i;
    *value = i * 10;
    ht_insert(table, key, value);

    assert(ht_contain(table, key) == 1);
    assert(*(int *)ht_lookup(table, key)->value == *value);

    if (i == 3) {
      assert(table->capacity == 8);
    }

    if (i == 6) {
      assert(table->capacity == 16);
    }

    if (i == 12) {
      assert(table->capacity == 32);
    }
  }

  printf("pass capacity test\n");

  // Verify all elements are still accessible after multiple resizes
  for (int i = 0; i < 20; i++) {
    int key = i;
    assert(ht_contain(table, &key) == 1);
    assert(*(int *)ht_lookup(table, &key)->value == i * 10);
  }

  printf("Resize test passed successfully!\n");
  assert(ht_free(table) == 0);
}

int main(void) {
  // test1();
  // test2();
  test_resize();
  printf("All tests passed!\n");
  return 0;
}