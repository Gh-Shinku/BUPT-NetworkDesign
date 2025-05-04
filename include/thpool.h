#ifndef THPOOL_H
#define THPOOL_H

#include <stdint.h>

typedef void *(*job_func)(void *);
typedef struct thpool_ *threadpool;

threadpool thpool_init(uint32_t num);
void thpool_add_job(threadpool pool, job_func func, void *arg);
void thpool_wait(threadpool pool);
void thpool_destroy(threadpool pool);

#endif /* THPOOL_H */
