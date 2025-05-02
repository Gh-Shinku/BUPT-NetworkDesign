#include "cache.h"

#include <stdlib.h>
#include <string.h>

// ip_table_t *ip_table_init() {
//   ip_table_t *ip_table = (ip_table_t *)malloc(sizeof(ip_table_t));
//   memset(ip_table, 0, sizeof(ip_table_t));
//   return ip_table;
// }

cache_node_t *cache_node_init(char *domain, array_t *ip_arr) {
  cache_node_t *cache_node = (cache_node_t *)malloc(sizeof(cache_node_t));
  memset(cache_node, 0, sizeof(cache_node_t));
  cache_node->domain = domain;
  cache_node->ip_table = ip_arr;
  return cache_node;
}

list_node_t *list_node_init() {
  list_node_t *list_node = (list_node_t *)malloc(sizeof(list_node_t));
  list_node->prev = NULL;
  list_node->next = NULL;
  list_node->value = NULL;
  return list_node;
}

cache_table_t *cache_init() {
  cache_table_t *list = (cache_table_t *)malloc(sizeof(cache_table_t));
  list->head = NULL;
  list->tail = NULL;
  list->hashtable = ht_init(NULL, ht_str_comp, 1024, STRING);
  list->size = 0;
  return list;
}

void cache_insert(cache_table_t *list, cache_node_t *value) {
  if (list->size >= CACHE_SIZE) {
    cache_node_t *cache_node = (cache_node_t *)list->tail->value;
    ht_delete(list->hashtable, cache_node->domain);
    cache_delete(list, list->tail);
    --list->size;
  }
  list_node_t *node = list_node_init();
  node->next = list->head;
  node->value = value; /* 指向实际的 value */
  if (list->head != NULL) list->head->prev = node;
  list->head = node;
  ++list->size;
}

void cache_delete(cache_table_t *list, list_node_t *node) {
  if (node->prev != NULL) {
    node->prev->next = node->next;
  }
  if (node->next != NULL) {
    node->next->prev = node->prev;
  }
  free(node->value);
  free(node);
}

cache_node_t *cache_lookup(cache_table_t *list, void *key) {
  ht_node_t *node = ht_lookup(list->hashtable, key);
  return (node == NULL ? NULL : (cache_node_t *)node->value);
}

void cache_free(cache_table_t *list) {
  for (list_node_t *node = list->head; node != NULL;) {
    free(node->value->domain);
    for (int i = 0; i < node->value->ip_table->length; ++i) {
      free(array_index(node->value->ip_table, i, char *));
    }
    array_free(node->value->ip_table);
    list_node_t *next = node->next;
    free(node->value);
    free(node);
    node = next;
  }
  free(list->hashtable);
  free(list);
}