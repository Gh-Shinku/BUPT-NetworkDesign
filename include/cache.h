#ifndef CACHE_H
#define CACHE_H
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "array.h"
#include "hashtable.h"
#include "stdbool.h"

#define CACHE_SIZE 512

typedef struct LocalRecord {
  char *domain;
  char *ip;
} local_record_t;

typedef struct CacheNode {
  char *domain; /* 与 hashtable 配合使用时有这个 key 更加方便 */
  array_t *RRs; /* Array of DnsResourceRecord */
  time_t update_time;
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
} lru_cache_t;

/**
 * @brief 初始化 local record
 *
 * @param domain
 * @param ip
 *
 * @return local_record_t*
 */
local_record_t *local_record_init(char *domain, char *ip);

/**
 * @brief 初始化 cache node
 *
 * @param domain
 * @param RR
 *
 * @return cache_node_t*
 */
cache_node_t *cache_node_init(char *domain, array_t *RRs);

/**
 * @brief 构造 list_node_t
 *
 * @return list_node_t*
 */
list_node_t *list_node_init();

/**
 * @brief 构造 lru_cache_t
 *
 * @return lru_cache_t*
 */
lru_cache_t *lru_cache_init();

/**
 * @brief 向 lru_cache_t 插入 cache_node_t
 *
 * @param list
 * @param value
 *
 */
void cache_insert(lru_cache_t *list, cache_node_t *value);

/**
 * @brief 从 lru_cache_t 删除指定 node
 * @note 不使用 key 进行查找的原因可以同时释放 cache_node_t 构造时申请的内存
 * @param list
 * @param node
 *
 */
void cache_delete(lru_cache_t *list, list_node_t *node);

/**
 * @brief 从 lru_cache_t 查找指定键值
 *
 * @param list
 * @param key
 *
 * @return cache_node_t*
 */
cache_node_t *cache_lookup(lru_cache_t *list, void *key);

/**
 * @brief
 *
 * @param node
 *
 * @return bool
 */
bool cache_is_expired(cache_node_t *node);

/**
 * @brief 清理 ttl 超时的 cache_node_t
 *
 * @param list
 *
 */
void cache_cleanup_expired(lru_cache_t *list);

/**
 * @brief 释放清理 lru_cache_t
 *
 * @param list
 *
 */
void cache_free(lru_cache_t *list);

#endif /* CACHE_H */