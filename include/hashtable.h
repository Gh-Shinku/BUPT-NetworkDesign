#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdint.h>

#define RESIZE_THRESHOLD 0.75

/* 除了字符串的长度不确定，其他类型的长度都是确定的 */
typedef enum KEY_TYPE { STRING } KEY_TYPE;

typedef uint32_t (*ht_hash_func)(void *, uint32_t, uint32_t);
typedef int (*ht_compare_func)(void *, void *, uint32_t);

typedef struct HTNode {
  struct HTNode *prev, *next;
  void *key;
  void *value;
} ht_node_t;

typedef void (*ht_clear_func)(ht_node_t *);

typedef struct HashTable {
  ht_node_t **nodes;    /* 表 */
  ht_hash_func hash;    /* 哈希函数 */
  ht_compare_func comp; /* 比较函数 */
  ht_clear_func clear;
  uint32_t capacity; /* 容量 */
  uint32_t size;     /* 实际数目 */
  uint32_t key_size;
} hash_table_t;

/**
 * @brief 字符串作为 key 的比较函数
 *
 * @param s1
 * @param s2
 * @param key_size
 *
 * @return 0 on euqal
 */
int ht_str_comp(void *s1, void *s2, uint32_t key_size);

/**
 * @brief 初始化哈希表节点
 *
 * @param key
 * @param value
 *
 * @return ht_node_t*
 */
ht_node_t *ht_node_init(void *key, void *value);

/**
 * @brief 初始化哈希表
 *
 * @param hash
 * @param capacity
 *
 * @return hash_table_t*
 */
hash_table_t *ht_init(ht_hash_func hash, ht_compare_func comp, ht_clear_func clear, uint32_t capacity, uint32_t key_size);

/**
 * @brief 向 Hash 表插入 k-v 对
 *
 * @note 不论 key/value 是什么类型，都应由 caller 负责其生命周期
 *
 * @param table 正确初始化后的哈希表指针
 * @param key key 指针
 * @param value value 指针
 *
 * @return
 */
void ht_insert(hash_table_t *table, void *key, void *value);

/**
 * @brief 检测 Hash 表中是否存在该 key
 *
 * @param table
 * @param key
 *
 * @return 1 on success, 0 otherwise
 */
int ht_contain(hash_table_t *table, void *key);

/**
 * @brief 在 Hash 表中查询 key 对应的 value
 *
 * @param table
 * @param key
 *
 * @return ht_node_t*
 */
ht_node_t *ht_lookup(hash_table_t *table, void *key);

/**
 * @brief 删除指定键值对
 *
 * @param table
 * @param key
 *
 */
void ht_delete(hash_table_t *table, void *key);

/**
 * @brief 释放 hash 表，调用 clear 进行具体节点内存回收
 *
 * @param table
 *
 */
void ht_free(hash_table_t *table);

/**
 * @brief Resize the hash table to a new capacity
 *
 * @param table Hash table to resize
 * @param new_capacity New capacity for the hash table
 *
 * @return 0 on success, 1 otherwise
 */
int ht_resize(hash_table_t *table, uint32_t new_capacity);

#endif /* HASHTABLE_H */