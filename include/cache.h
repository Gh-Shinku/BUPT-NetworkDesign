#ifndef CACHE_H
#define CACHE_H
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "array.h"
#include "hashtable.h"

#define CACHE_SIZE 1024

typedef struct CacheNode {
  char *domain;
  array_t *ip_table; /* array of char* */
  uint32_t ttl;      /* TTL in seconds */
  time_t timestamp;  /* When this entry was created/updated */
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

cache_node_t *cache_node_init(char *domain, array_t *ip_arr);
cache_node_t *cache_node_init_with_ttl(char *domain, array_t *ip_arr, uint32_t ttl);
list_node_t *list_node_init();
cache_table_t *cache_init();

void cache_insert(cache_table_t *list, cache_node_t *value);
void cache_delete(cache_table_t *list, list_node_t *node);
cache_node_t *cache_lookup(cache_table_t *list, void *key);
void cache_move_to_front(cache_table_t *list, cache_node_t *node);
void cache_cleanup_expired(cache_table_t *list);
void cache_free(cache_table_t *list);

int cache_is_expired(cache_node_t *node);

#endif /* CACHE_H */