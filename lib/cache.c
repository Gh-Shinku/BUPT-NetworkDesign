#include "cache.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_TTL 360

cache_node_t *cache_node_init(char *domain, array_t *ip_arr) {
  return cache_node_init_with_ttl(domain, ip_arr, DEFAULT_TTL);
}

cache_node_t *cache_node_init_with_ttl(char *domain, array_t *ip_arr, uint32_t ttl) {
  cache_node_t *cache_node = (cache_node_t *)malloc(sizeof(cache_node_t));
  if (cache_node == NULL) return NULL;

  memset(cache_node, 0, sizeof(cache_node_t));
  cache_node->domain = domain;
  cache_node->ip_table = ip_arr;
  cache_node->ttl = ttl;
  cache_node->timestamp = time(NULL);
  return cache_node;
}

list_node_t *list_node_init() {
  list_node_t *list_node = (list_node_t *)malloc(sizeof(list_node_t));
  if (list_node == NULL) return NULL;

  list_node->prev = NULL;
  list_node->next = NULL;
  list_node->value = NULL;
  return list_node;
}

cache_table_t *cache_init() {
  cache_table_t *list = (cache_table_t *)malloc(sizeof(cache_table_t));
  if (list == NULL) return NULL;

  list->head = NULL;
  list->tail = NULL;
  list->hashtable = ht_init(NULL, ht_str_comp, 1024, STRING);
  list->size = 0;
  return list;
}

int cache_is_expired(cache_node_t *node) {
  if (node == NULL) return 1;
  time_t now = time(NULL);
  return (now - node->timestamp) > node->ttl;
}

void cache_move_to_front(cache_table_t *list, cache_node_t *node) {
  if (list == NULL || node == NULL) return;

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
  cur_node->prev = NULL;
  if (list->head) list->head->prev = cur_node;
  list->head = cur_node;
}

void cache_cleanup_expired(cache_table_t *list) {
  if (list == NULL) return;

  list_node_t *cur_node = list->tail;
  list_node_t *prev = NULL;

  while (cur_node != NULL) {
    prev = cur_node->prev;
    cache_node_t *entry = cur_node->value;

    if (entry && cache_is_expired(entry)) {
      if (entry->domain) {
        ht_delete(list->hashtable, entry->domain);
        free(entry->domain);
      }

      if (cur_node->prev) cur_node->prev->next = cur_node->next;
      if (cur_node->next) cur_node->next->prev = cur_node->prev;

      if (list->head == cur_node) list->head = cur_node->next;
      if (list->tail == cur_node) list->tail = cur_node->prev;

      if (entry->ip_table) {
        for (int i = 0; i < entry->ip_table->length; ++i) {
          char *ip = array_index(entry->ip_table, i, char *);
          if (ip) free(ip);
        }
        array_free(entry->ip_table);
      }

      free(entry);
      free(cur_node);
      --list->size;
    }

    cur_node = prev;
  }
}

void cache_insert(cache_table_t *list, cache_node_t *value) {
  if (list == NULL || value == NULL) return;

  cache_cleanup_expired(list);

  if (list->size >= CACHE_SIZE && list->tail != NULL) {
    char *domain = NULL;
    if (list->tail->value && list->tail->value->domain) {
      domain = strdup(list->tail->value->domain);
    }

    cache_delete(list, list->tail);

    if (domain) {
      ht_delete(list->hashtable, domain);
      free(domain);
    }
  }

  list_node_t *node = list_node_init();
  if (node == NULL) return;

  node->value = value;
  node->next = list->head;
  if (list->head != NULL) {
    list->head->prev = node;
  }
  list->head = node;

  if (list->tail == NULL) {
    list->tail = node;
  }

  if (value->domain) {
    ht_insert(list->hashtable, value->domain, value);
  }

  ++list->size;
}

void cache_delete(cache_table_t *list, list_node_t *node) {
  if (list == NULL || node == NULL) return;

  if (node == list->head) list->head = node->next;
  if (node == list->tail) list->tail = node->prev;

  if (node->prev != NULL) node->prev->next = node->next;
  if (node->next != NULL) node->next->prev = node->prev;

  if (node->value != NULL) {
    if (node->value->domain) {
      free(node->value->domain);
    }

    if (node->value->ip_table) {
      for (int i = 0; i < node->value->ip_table->length; ++i) {
        char *ip = array_index(node->value->ip_table, i, char *);
        if (ip) free(ip);
      }
      array_free(node->value->ip_table);
    }

    free(node->value);
  }

  free(node);
  list->size--;
}

cache_node_t *cache_lookup(cache_table_t *list, void *key) {
  if (list == NULL || key == NULL || list->hashtable == NULL) return NULL;

  ht_node_t *ht_node = ht_lookup(list->hashtable, key);
  if (ht_node == NULL) return NULL;

  cache_node_t *cache_node = (cache_node_t *)ht_node->value;
  if (cache_node == NULL) return NULL;

  cache_move_to_front(list, cache_node);

  return cache_node;
}

void cache_free(cache_table_t *list) {
  if (list == NULL) return;

  list_node_t *node = list->head;
  while (node != NULL) {
    list_node_t *next = node->next;

    if (node->value) {
      if (node->value->domain) {
        free(node->value->domain);
      }

      if (node->value->ip_table) {
        for (int i = 0; i < node->value->ip_table->length; ++i) {
          char *ip = array_index(node->value->ip_table, i, char *);
          if (ip) free(ip);
        }
        array_free(node->value->ip_table);
      }

      free(node->value);
    }

    free(node);
    node = next;
  }

  if (list->hashtable) {
    ht_free(list->hashtable);
  }

  free(list);
}