#ifndef LIST_H
#define LIST_H
#include <stdint.h>

#include "array.h"
#include "hashtable.h"

#define CACHE_SIZE 1024
#define IP_TABLE_SIZE 8

typedef struct CacheNode {
  char *domain;
  array_t *ip_table; /* array of char* */
} cache_node_t;

typedef struct ListNode {
  struct ListNode *prev;
  struct ListNode *next;
  cache_node_t *value;
} list_node_t;

typedef struct Cache {
  list_node_t *head;
  list_node_t *tail;
  hash_table_t *hashtable;
  uint32_t size;
} cache_table_t;

// ip_table_t *ip_table_init();

cache_node_t *cache_node_init();

list_node_t *list_node_init();

cache_table_t *cache_init();

void cache_insert(cache_table_t *list, cache_node_t *value);

void cache_delete(cache_table_t *list, list_node_t *node);

cache_node_t *cache_lookup(cache_table_t *list, void *key);

void cache_free(cache_table_t *list);

#endif /* LIST_H */