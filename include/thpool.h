#ifndef THPOOL_H
#define THPOOL_H

#include <stdint.h>

typedef void *(*job_func)(void *);
typedef struct thpool_ *threadpool;

/**
 * @brief 线程池构造函数
 *
 * @param num
 *
 * @return threadpool
 */
threadpool thpool_init(uint32_t num);

/**
 * @brief 添加工作函数
 *
 * @param pool
 * @param func
 * @param arg
 *
 */
void thpool_add_job(threadpool pool, job_func func, void *arg);

/**
 * @brief 等待线程退出
 *
 * @param pool
 *
 */
void thpool_wait(threadpool pool);

/**
 * @brief 销毁线程池
 *
 * @param pool
 *
 */
void thpool_destroy(threadpool pool);

#endif /* THPOOL_H */
