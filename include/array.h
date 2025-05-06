#ifndef ARRAY_H
#define ARRAY_H
#include <stdint.h>
#include <stdlib.h>
#define DEFAULT_CAPACITY 8

typedef struct Array {
  uint32_t capacity; /* 容量 */
  uint32_t length;   /* 下一个元素的待插入索引/实际个数 */
  uint32_t e_size;   /* 元素大小 */
  void *table;
} array_t;

/**
 * @brief 动态数组初始化，若元素非基本类型，需由 caller 维护元素内存分配
 *
 * @param e_size
 *
 * @return array_t*
 */
array_t *array_init(uint32_t e_size);

/**
 * @brief 在数组尾插入元素
 *
 * @param array
 * @param value
 *
 */
void array_append(array_t *array, void *value);

/**
 * @brief 返回动态数组指定索引处元素的地址，建议使用更方便的 array_index
 *
 * @param array
 * @param index
 *
 * @return void*
 */
void *_array_index(array_t *array, uint32_t index);

/**
 * @brief 实际仍然调用 _array_index，追加了对空指针的判断，更为安全
 *
 * @param array
 * @param index
 *
 * @return void*
 */
void *safe_array_index(array_t *array, uint32_t index);

/* 返回动态数组指定索引处元素 */
#define array_index(a, i, t) (*(t *)safe_array_index((a), (i)))

/**
 * @brief 释放动态数组申请的内存
 *
 * @param array
 *
 */
void array_free(array_t *array);

#endif /* ARRAY_H */