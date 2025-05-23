#include "hashtable.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

static uint32_t fnv_hash_1a_32(void *key, uint32_t len) {
  uint8_t *p = key;
  uint32_t h = 0x811c9dc5;
  for (uint32_t i = 0; i < len; i++) h = (h ^ p[i]) * 0x01000193;
  return h;
}

static uint64_t fnv_hash_1a_64(void *key, uint32_t len) {
  uint8_t *p = key;
  uint64_t h = 0xcbf29ce484222325ULL;
  for (uint32_t i = 0; i < len; i++) h = (h ^ p[i]) * 0x100000001b3ULL;
  return h;
}

static uint32_t ht_hash(void *key, uint32_t key_size, uint32_t capacity) {
  if (key_size == STRING) {
    return fnv_hash_1a_32(key, strlen((const char *)key)) % capacity;
  } else {
    return fnv_hash_1a_32(key, key_size) % capacity;
  }
}

int ht_str_comp(void *s1, void *s2, uint32_t key_size) {
  assert(s1 && s2);
  return strcmp((const char *)s1, (const char *)s2);
}

static int ht_default_comp(void *s1, void *s2, uint32_t key_size) {
  return memcmp(s1, s2, key_size);
}

hash_table_t *ht_init(ht_hash_func hash, ht_compare_func comp, ht_clear_func clear, uint32_t capacity, uint32_t key_size) {
  hash_table_t *table = (hash_table_t *)malloc(sizeof(hash_table_t));
  if (hash != NULL) {
    table->hash = hash;
  } else {
    table->hash = ht_hash;
  }
  if (comp != NULL) {
    table->comp = comp;
  } else {
    table->comp = ht_default_comp;
  }
  assert(clear);
  table->clear = clear;
  table->capacity = capacity;
  table->size = 0;
  table->key_size = key_size;
  table->nodes = (ht_node_t **)malloc(sizeof(ht_node_t *) * table->capacity);
  memset(table->nodes, 0, sizeof(ht_node_t *) * table->capacity);
  return table;
}

int ht_resize(hash_table_t *table, uint32_t new_capacity) {
  ht_node_t **new_nodes = (ht_node_t **)malloc(sizeof(ht_node_t *) * new_capacity);
  if (new_nodes == NULL) return 1;

  memset(new_nodes, 0, sizeof(ht_node_t *) * new_capacity);

  uint32_t old_capacity = table->capacity;
  ht_node_t **old_nodes = table->nodes;

  table->nodes = new_nodes;
  table->capacity = new_capacity;
  table->size = 0;

  for (uint32_t i = 0; i < old_capacity; i++) {
    ht_node_t *current = old_nodes[i];

    while (current != NULL) {
      ht_node_t *next = current->next;

      ht_insert(table, current->key, current->value);

      current = next;
    }
  }

  free(old_nodes);

  return 0;
}

ht_node_t *ht_node_init(void *key, void *value) {
  ht_node_t *new_node = (ht_node_t *)malloc(sizeof(ht_node_t));
  new_node->prev = NULL;
  new_node->next = NULL;
  new_node->key = key;
  new_node->value = value;
  return new_node;
}

void ht_insert(hash_table_t *table, void *key, void *value) {
  assert(table != NULL && key != NULL && value != NULL);

  if ((float)table->size / table->capacity >= RESIZE_THRESHOLD) {
    ht_resize(table, table->capacity * 2);
  }

  uint32_t index = table->hash(key, table->key_size, table->capacity);
  ht_node_t *new_node = NULL;
  if (table->nodes[index] != NULL) /* 有碰撞 */ {
    for (ht_node_t *node = table->nodes[index]; node != NULL; node = node->next) {
      if (!table->comp(node->key, key, table->key_size)) /* 重复节点，更新 k-v pair */ {
        // debug_log();
        // printf("node->key: %s, key: %s\n", (char *)node->key, (char *)key);
        table->clear(node);
        node->key = key;
        node->value = value;
        return;
      }
    }
    new_node = ht_node_init(key, value);
    new_node->next = table->nodes[index];
    table->nodes[index]->prev = new_node;
  } else /* 无碰撞 */ {
    new_node = ht_node_init(key, value);
  }
  table->nodes[index] = new_node;
  ++table->size;
}

int ht_contain(hash_table_t *table, void *key) {
  uint32_t index = table->hash(key, table->key_size, table->capacity);
  for (ht_node_t *node = table->nodes[index]; node != NULL; node = node->next) {
    if (!table->comp(node->key, key, table->key_size)) {
      return 1;
    }
  }
  return 0;
}

ht_node_t *ht_lookup(hash_table_t *table, void *key) {
  assert(table != NULL && key != NULL);
  uint32_t index = table->hash(key, table->key_size, table->capacity);
  for (ht_node_t *node = table->nodes[index]; node != NULL; node = node->next) {
    assert(key);
    assert(node->key);
    if (!table->comp(node->key, key, table->key_size)) {
      return node;
    }
  }
  return NULL;
}

void ht_delete(hash_table_t *table, void *key) {
  uint32_t index = table->hash(key, table->key_size, table->capacity);
  for (ht_node_t *node = table->nodes[index]; node != NULL;) {
    ht_node_t *next = node->next;
    if (!table->comp(node->key, key, table->key_size)) {
      if (node->next != NULL) {
        node->next->prev = node->prev;
      }
      if (node->prev != NULL) {
        node->prev->next = node->next;
      }
      if (node->prev == NULL && node->next == NULL) {
        table->nodes[index] = NULL;
      }
      table->clear(node);
      free(node);
    }
    node = next;
    --table->size;
  }
}

void ht_free(hash_table_t *table) {
  for (int i = 0; i < table->capacity; ++i) {
    if (table->nodes[i] != NULL) {
      for (ht_node_t *node = table->nodes[i]; node != NULL;) {
        ht_node_t *next = node->next;
        table->clear(node);
        free(node);
        node = next;
      }
    }
  }
  free(table->nodes);
  free(table);
}