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
  assert(ht_insert(table, k, v) == HT_SUCCESS);
  assert(ht_contain(table, k) == HT_SUCCESS);
  assert(*(int *)ht_lookup(table, k) == *v);
  assert(ht_destroy(table) == HT_SUCCESS);
}

static void test2() {
  hash_table_t *table = ht_init(NULL, ht_str_comp, 16, STRING);
  const char *s = "www.baidu.com";
  const char *v = "192.168.1.1";
  char *ss = strdup(s);
  char *vv = strdup(v);
  assert(ht_insert(table, ss, vv) == HT_SUCCESS);
  assert(ht_contain(table, ss) == HT_SUCCESS);
  assert(strcmp((char *)ht_lookup(table, ss), vv) == 0);
  assert(ht_destroy(table) == HT_SUCCESS);
}

int main(void) {
  test1();
  test2();
  return 0;
}