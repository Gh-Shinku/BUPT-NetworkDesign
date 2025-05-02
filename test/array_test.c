#include "array.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void static test1() {
  array_t *array = array_init(sizeof(int));
  for (int i = 0; i < 1000; ++i) {
    array_append(array, &i);
  }
  for (int i = 0; i < array->length; ++i) {
    printf("%d\n", array_index(array, i, int));
  }
}

void static test2() {
  array_t *array = array_init(sizeof(char *));
  for (int i = 0; i < 100; ++i) {
    char *str = strdup("Man! What can i say?");
    array_append(array, &str);
  }
  for (int i = 0; i < array->length; ++i) {
    char *str = array_index(array, i, char *);
    printf("%d: %s\n", i, str);
    free(str);
  }
  array_free(array);
}

int main() {
  printf("fuck\n");
  test2();
  return 0;
}