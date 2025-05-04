#include "thpool.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *task_function(void *arg) {
  int num = *(int *)arg;
  printf("Thread %lu is processing task %d\n", pthread_self(), num);
  usleep(500000);  // 模拟任务耗时 0.5 秒
  free(arg);       // 注意释放参数内存
  return NULL;
}

int main() {
  int num_threads = 4;
  int num_tasks = 10;

  printf("Initializing thread pool with %d threads\n", num_threads);
  threadpool pool = thpool_init(num_threads);
  if (!pool) {
    fprintf(stderr, "Failed to create thread pool.\n");
    return 1;
  }

  printf("Submitting %d tasks\n", num_tasks);
  for (int i = 0; i < num_tasks; ++i) {
    int *arg = malloc(sizeof(int));
    *arg = i + 1;
    thpool_add_job(pool, task_function, arg);
  }

  printf("Waiting for all tasks to complete...\n");
  thpool_wait(pool);

  printf("All tasks completed. Destroying thread pool.\n");
  thpool_destroy(pool);

  printf("Thread pool destroyed. Exiting.\n");
  return 0;
}
