#include "cache.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dns.h"

local_record_t *local_record_init(char *domain, char *ip) {
  assert(domain && ip);
  local_record_t *record = (local_record_t *)malloc(sizeof(local_record_t));
  assert(record);
  memset(record, 0, sizeof(local_record_t));
  record->domain = strdup(domain);
  record->ip = strdup(ip);
  return record;
}

cache_node_t *cache_node_init(char *domain, array_t *RRs) {
  assert(domain && RRs);
  cache_node_t *cache_node = (cache_node_t *)malloc(sizeof(cache_node_t));
  assert(cache_node != NULL);
  memset(cache_node, 0, sizeof(cache_node_t));
  cache_node->domain = strdup(domain);
  cache_node->RRs = RRs;
  cache_node->update_time = time(NULL);
  return cache_node;
}

list_node_t *list_node_init() {
  list_node_t *list_node = (list_node_t *)malloc(sizeof(list_node_t));
  assert(list_node != NULL);

  memset(list_node, 0, sizeof(list_node_t));
  return list_node;
}

lru_cache_t *lru_cache_init() {
  lru_cache_t *list = (lru_cache_t *)malloc(sizeof(lru_cache_t));
  assert(list != NULL);

  list->head = NULL;
  list->tail = NULL;
  list->hashtable = ht_init(NULL, ht_str_comp, 1024, STRING);
  list->size = 0;
  return list;
}

bool cache_is_expired(cache_node_t *node) {
  assert(node != NULL);
  time_t now = time(NULL);
  DnsResourceRecord *RR = &array_index(node->RRs, 0, DnsResourceRecord);
  return (now - node->update_time) > RR->ttl;
}

static void cache_move_to_front(lru_cache_t *list, cache_node_t *node) {
  assert(list != NULL && node != NULL);

  list_node_t *cur_node = list->head;
  while (cur_node != NULL && cur_node->value != node) {
    cur_node = cur_node->next;
  }

  if (cur_node == NULL || cur_node == list->head) return;

  if (cur_node->prev) cur_node->prev->next = cur_node->next;
  if (cur_node->next) cur_node->next->prev = cur_node->prev;

  if (cur_node == list->tail) {
    list->tail = cur_node->prev;
  }

  cur_node->next = list->head;
  list->head->prev = cur_node;
  cur_node->prev = NULL;
  list->head = cur_node;
}

void cache_cleanup_expired(lru_cache_t *list) {
  assert(list != NULL);

  /* 从链表尾部先开始清理 */
  list_node_t *cur_node = list->tail;
  list_node_t *prev = NULL;

  while (cur_node != NULL) {
    prev = cur_node->prev;
    cache_node_t *entry = cur_node->value;

    if (cache_is_expired(entry)) {
      cache_delete(list, cur_node);
    }

    cur_node = prev;
  }
}

void cache_insert(lru_cache_t *list, cache_node_t *value) {
  assert(list != NULL && value != NULL);

  /* 缓存满了，进行清理 */
  if (list->size >= CACHE_SIZE) {
    cache_cleanup_expired(list);
    if (list->size >= CACHE_SIZE) cache_delete(list, list->tail);
  }

  list_node_t *node = list_node_init();

  node->value = value;
  node->next = list->head;
  if (list->head != NULL) {
    list->head->prev = node;
  }
  list->head = node;

  if (list->tail == NULL) {
    list->tail = node;
  }

  ht_insert(list->hashtable, value->domain, value);

  ++list->size;
}

void cache_delete(lru_cache_t *list, list_node_t *node) {
  assert(list != NULL && node != NULL);

  if (node == list->head) list->head = node->next;
  if (node == list->tail) list->tail = node->prev;

  if (node->prev != NULL) node->prev->next = node->next;
  if (node->next != NULL) node->next->prev = node->prev;

  /* 释放 hashtable 中对应项 */
  cache_node_t *entry = node->value;
  ht_delete(list->hashtable, entry->domain);

  /* 释放 cache_node_t->domain */
  free(entry->domain);

  /* 释放 cache_node_t->RRs */
  for (int i = 0; i < entry->RRs->length; ++i) {
    DnsResourceRecord *RR = &array_index(entry->RRs, i, DnsResourceRecord);
    RR_delete(RR);
    array_free(entry->RRs);
  }
  /* 释放 cache_node_t */
  free(entry);

  /* 释放 list_node_t */
  free(node);
  --list->size;
}

cache_node_t *cache_lookup(lru_cache_t *list, void *key) {
  assert(list != NULL && key != NULL);

  ht_node_t *ht_node = ht_lookup(list->hashtable, key);
  if (ht_node == NULL) return NULL;

  cache_node_t *cache_node = (cache_node_t *)ht_node->value;
  assert(cache_node != NULL);

  cache_move_to_front(list, cache_node);

  return cache_node;
}

void cache_free(lru_cache_t *list) {
  assert(list != NULL);

  /* 释放链表 */
  list_node_t *node = list->head;
  while (node != NULL) {
    list_node_t *next = node->next;
    cache_delete(list, node);
    node = next;
  }

  /* 释放哈希表 */
  ht_free(list->hashtable);

  free(list);
}
