#include "thpool.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

#define MAX_THREAD 64

typedef struct job {
  struct job *next;
  job_func func;
  void *arg;
} job_t;

typedef struct jobqueue_ {
  job_t *head;
  job_t *tail;
  uint32_t len;
} jobqueue_t;

typedef struct thpool_ {
  pthread_t *threads;
  uint32_t num_threads_working;
  uint32_t num_threads_total;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  pthread_cond_t wait_cond;
  jobqueue_t job_queue;
  volatile int is_alive;
} thpool_t;

static void *thread_worker(void *arg);
static void jobqueue_push(thpool_t *thpool, job_func func, void *arg);
static job_t *jobqueue_pop(jobqueue_t *jobqueue);

threadpool thpool_init(uint32_t num) {
  if (num == 0 || num > MAX_THREAD) num = MAX_THREAD;

  thpool_t *thpool = (thpool_t *)malloc(sizeof(thpool_t));
  assert(thpool != NULL);

  thpool->threads = (pthread_t *)malloc(sizeof(pthread_t) * num);
  thpool->num_threads_working = 0;
  thpool->num_threads_total = num;
  thpool->job_queue.head = NULL;
  thpool->job_queue.tail = NULL;
  thpool->job_queue.len = 0;
  thpool->is_alive = 1;

  pthread_mutex_init(&thpool->mutex, NULL);
  pthread_cond_init(&thpool->cond, NULL);
  pthread_cond_init(&thpool->wait_cond, NULL);

  for (uint32_t i = 0; i < num; ++i) {
    pthread_create(&thpool->threads[i], NULL, thread_worker, thpool);
  }

  return thpool;
}

void thpool_add_job(threadpool pool, job_func func, void *arg) {
  thpool_t *thpool = (thpool_t *)pool;

  pthread_mutex_lock(&thpool->mutex);
  jobqueue_push(thpool, func, arg);
  pthread_cond_signal(&thpool->cond);
  pthread_mutex_unlock(&thpool->mutex);
}

void thpool_wait(threadpool pool) {
  thpool_t *thpool = (thpool_t *)pool;

  pthread_mutex_lock(&thpool->mutex);
  while (thpool->job_queue.len > 0 || thpool->num_threads_working > 0) {
    pthread_cond_wait(&thpool->wait_cond, &thpool->mutex);
  }
  pthread_mutex_unlock(&thpool->mutex);
}

static void *thread_worker(void *arg) {
  thpool_t *thpool = (thpool_t *)arg;
  job_t *job;

  while (1) {
    pthread_mutex_lock(&thpool->mutex);

    while (thpool->job_queue.len == 0 && thpool->is_alive) {
      pthread_cond_wait(&thpool->cond, &thpool->mutex);
    }

    if (!thpool->is_alive) {
      pthread_mutex_unlock(&thpool->mutex);
      break;
    }

    ++thpool->num_threads_working;
    job = jobqueue_pop(&thpool->job_queue);
    pthread_mutex_unlock(&thpool->mutex);

    if (job) {
      job->func(job->arg);
      free(job);
    }

    pthread_mutex_lock(&thpool->mutex);
    --thpool->num_threads_working;
    if (thpool->job_queue.len == 0 && thpool->num_threads_working == 0) {
      pthread_cond_broadcast(&thpool->wait_cond);
    }
    pthread_mutex_unlock(&thpool->mutex);
  }
  return NULL;

  return NULL;
}

void thpool_destroy(threadpool pool) {
  thpool_t *thpool = (thpool_t *)pool;
  if (!thpool) return;

  pthread_mutex_lock(&thpool->mutex);
  thpool->is_alive = 0;
  pthread_cond_broadcast(&thpool->cond);  // 唤醒所有等待线程
  pthread_mutex_unlock(&thpool->mutex);

  thpool_wait(pool);

  for (uint32_t i = 0; i < thpool->num_threads_total; ++i) {
    pthread_join(thpool->threads[i], NULL);
  }

  job_t *job;
  while ((job = jobqueue_pop(&thpool->job_queue)) != NULL) {
    free(job);
  }

  pthread_mutex_destroy(&thpool->mutex);
  pthread_cond_destroy(&thpool->cond);
  pthread_cond_destroy(&thpool->wait_cond);
  free(thpool->threads);
  free(thpool);
}

static void jobqueue_push(thpool_t *thpool, job_func func, void *arg) {
  job_t *new_job = (job_t *)malloc(sizeof(job_t));
  new_job->func = func;
  new_job->arg = arg;
  new_job->next = NULL;

  if (thpool->job_queue.tail) {
    thpool->job_queue.tail->next = new_job;
    thpool->job_queue.tail = new_job;
  } else {
    thpool->job_queue.head = new_job;
    thpool->job_queue.tail = new_job;
  }

  ++thpool->job_queue.len;
}

static job_t *jobqueue_pop(jobqueue_t *jobqueue) {
  job_t *job = jobqueue->head;
  if (job) {
    jobqueue->head = job->next;
    if (jobqueue->head == NULL) jobqueue->tail = NULL;
    --jobqueue->len;
  }
  return job;
}
