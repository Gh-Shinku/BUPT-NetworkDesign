#include "array.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

array_t *array_init(uint32_t e_size) {
  array_t *array = (array_t *)malloc(sizeof(array_t));
  array->capacity = DEFAULT_CAPACITY;
  array->length = 0;
  array->e_size = e_size;
  array->table = (void *)malloc(array->e_size * array->capacity);
  return array;
}

void array_append(array_t *array, void *value) {
  if (array->length == array->capacity) {
    array->capacity *= 2;
    array->table = realloc(array->table, array->capacity * array->e_size);
    assert(array->table != NULL);
  }
  memcpy((array->table + array->e_size * array->length), value, array->e_size);
  ++array->length;
}

void *_array_index(array_t *array, uint32_t index) {
  if (index >= array->length) {
    perror("array index out of range");
    return NULL;
  }
  return (void *)(array->table + array->e_size * index);
}

void *safe_array_index(array_t *array, uint32_t index) {
  void *addr = _array_index(array, index);
  if (addr == NULL) {
    perror("the index of array is NULL");
    return NULL;
  }
  return addr;
}

void array_free(array_t *array) {
  free(array->table);
  free(array);
}