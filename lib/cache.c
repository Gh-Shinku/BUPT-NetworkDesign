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

  // Find the list node containing our cache node
  list_node_t *cur_node = list->head;
  while (cur_node != NULL && cur_node->value != node) {
    cur_node = cur_node->next;
  }

  // Not found or already at front
  if (cur_node == NULL || cur_node == list->head) return;

  // Remove from current position
  if (cur_node->prev) cur_node->prev->next = cur_node->next;
  if (cur_node->next) cur_node->next->prev = cur_node->prev;

  // Update tail if needed
  if (cur_node == list->tail) {
    list->tail = cur_node->prev;
  }

  // Move to front
  cur_node->next = list->head;
  cur_node->prev = NULL;
  if (list->head) list->head->prev = cur_node;
  list->head = cur_node;
}

void cache_cleanup_expired(cache_table_t *list) {
  if (list == NULL) return;

  list_node_t *cur_node = list->tail;
  list_node_t *prev;

  while (cur_node != NULL) {
    prev = cur_node->prev;  // Save prev before any modifications

    // Make sure the node and its value are valid before checking expiration
    if (cur_node->value && cache_is_expired(cur_node->value)) {
      // Save a reference to the domain for hashtable deletion
      char *domain = NULL;
      if (cur_node->value && cur_node->value->domain) {
        domain = strdup(cur_node->value->domain);  // Create a safe copy
      }

      // Update list pointers
      if (cur_node->prev) cur_node->prev->next = cur_node->next;
      if (cur_node->next) cur_node->next->prev = cur_node->prev;

      // Update head/tail if necessary
      if (list->head == cur_node) list->head = cur_node->next;
      if (list->tail == cur_node) list->tail = cur_node->prev;

      // Free cache node resources
      if (cur_node->value) {
        if (cur_node->value->domain) {
          free(cur_node->value->domain);
        }

        if (cur_node->value->ip_table) {
          for (int i = 0; i < cur_node->value->ip_table->length; ++i) {
            char *ip = array_index(cur_node->value->ip_table, i, char *);
            if (ip) free(ip);
          }
          array_free(cur_node->value->ip_table);
        }

        free(cur_node->value);
      }

      // Remove from hashtable using our safe copy of the domain
      if (domain) {
        ht_delete(list->hashtable, domain);
        free(domain);  // Free our copy
      }

      // Free the list node itself
      free(cur_node);
      --list->size;
    }

    cur_node = prev;
  }
}

void cache_insert(cache_table_t *list, cache_node_t *value) {
  if (list == NULL || value == NULL) return;

  // Clean up expired entries to make room
  cache_cleanup_expired(list);

  // If still full, remove LRU item (tail of list)
  if (list->size >= CACHE_SIZE && list->tail != NULL) {
    // Make a safe copy of the domain for hashtable lookup
    char *domain = NULL;
    if (list->tail->value && list->tail->value->domain) {
      domain = strdup(list->tail->value->domain);
    }

    // Delete the tail node
    cache_delete(list, list->tail);

    // Remove from hashtable
    if (domain) {
      ht_delete(list->hashtable, domain);
      free(domain);
    }
  }

  // Create new node and add to head of list
  list_node_t *node = list_node_init();
  if (node == NULL) return;

  node->value = value;
  node->next = list->head;
  if (list->head != NULL) {
    list->head->prev = node;
  }
  list->head = node;

  // If this is the first node, it's also the tail
  if (list->tail == NULL) {
    list->tail = node;
  }

  // Add to hashtable for O(1) lookups
  if (value->domain) {
    ht_insert(list->hashtable, value->domain, value);
  }

  ++list->size;
}

void cache_delete(cache_table_t *list, list_node_t *node) {
  if (list == NULL || node == NULL) return;

  // Remove from linked list
  if (node == list->head) list->head = node->next;
  if (node == list->tail) list->tail = node->prev;

  if (node->prev != NULL) node->prev->next = node->next;
  if (node->next != NULL) node->next->prev = node->prev;

  // Free the cache node data
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

  // Free the list node itself
  free(node);
  list->size--;
}

cache_node_t *cache_lookup(cache_table_t *list, void *key) {
  if (list == NULL || key == NULL || list->hashtable == NULL) return NULL;

  // Look up in hashtable
  ht_node_t *ht_node = ht_lookup(list->hashtable, key);
  if (ht_node == NULL) return NULL;

  cache_node_t *cache_node = (cache_node_t *)ht_node->value;
  if (cache_node == NULL) return NULL;

  // Check if entry has expired
  if (cache_is_expired(cache_node)) {
    // First make a safe copy of the key for hashtable deletion
    char *domain = NULL;
    if (cache_node->domain) {
      domain = strdup(cache_node->domain);
    }

    // Find and delete the list node
    list_node_t *cur_node = list->head;
    while (cur_node != NULL && cur_node->value != cache_node) {
      cur_node = cur_node->next;
    }

    if (cur_node != NULL) {
      cache_delete(list, cur_node);
    }

    // Remove from hashtable using our safe copy
    if (domain) {
      ht_delete(list->hashtable, domain);
      free(domain);
    }

    return NULL;
  }

  // Move to front of list (most recently used)
  cache_move_to_front(list, cache_node);

  return cache_node;
}

void cache_free(cache_table_t *list) {
  if (list == NULL) return;

  // Free all list nodes and their contents
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

  // Free the hashtable
  if (list->hashtable) {
    ht_free(list->hashtable);
  }

  // Free the cache table itself
  free(list);
}