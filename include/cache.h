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

/**
 * @brief 构造 cache_node_t
 *
 * @param domain
 * @param ip_arr
 *
 * @return cache_node_t*
 */
cache_node_t *cache_node_init(char *domain, array_t *ip_arr);

/**
 * @brief "重载" cache_node_init 可以指定 ttl
 *
 * @param domain
 * @param ip_arr
 * @param ttl
 *
 * @return cache_node_t*
 */
cache_node_t *cache_node_init_with_ttl(char *domain, array_t *ip_arr, uint32_t ttl);

/**
 * @brief 构造 list_node_t
 *
 * @return list_node_t*
 */
list_node_t *list_node_init();

/**
 * @brief 构造 cache_table_t
 *
 * @return cache_table_t*
 */
cache_table_t *cache_init();

/**
 * @brief 向 cache_table_t 插入 cache_node_t
 *
 * @param list
 * @param value
 *
 */
void cache_insert(cache_table_t *list, cache_node_t *value);

/**
 * @brief 从 cache_table_t 删除指定 node
 * @note 不使用 key 进行查找的原因可以同时释放 cache_node_t 构造时申请的内存
 * @param list
 * @param node
 *
 */
void cache_delete(cache_table_t *list, list_node_t *node);

/**
 * @brief 从 cache_table_t 查找指定键值
 *
 * @param list
 * @param key
 *
 * @return cache_node_t*
 */
cache_node_t *cache_lookup(cache_table_t *list, void *key);

/**
 * @brief 将 cache_node_t 移动到链表头
 *
 * @param list
 * @param node
 *
 */
void cache_move_to_front(cache_table_t *list, cache_node_t *node);

/**
 * @brief
 *
 * @param node
 *
 * @return int if expired 1 else 0
 */
int cache_is_expired(cache_node_t *node);

/**
 * @brief 清理 ttl 超时的 cache_node_t
 *
 * @param list
 *
 */
void cache_cleanup_expired(cache_table_t *list);

/**
 * @brief 释放清理 cache_table_t
 *
 * @param list
 *
 */
void cache_free(cache_table_t *list);

#endif /* CACHE_H */