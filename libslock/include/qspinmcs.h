/*
 * File: qspinmcs.h
 * Author: Tudor David <tudor.david@epfl.ch>, Vasileios Trigonakis <vasileios.trigonakis@epfl.ch>
 *
 * Description: 
 *      An implementation of a qspinmcs lock with:
 *       - proportional back-off optimization
 *       - pretetchw for write optitization for the AMD Opteron
 *           Magny-Cours processors
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Tudor David, Vasileios Trigonakis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


#ifndef _QSPINMCS_H_
#define _QSPINMCS_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#if defined(PLATFORM_NUMA)
#  include <numa.h>
#endif
#include <pthread.h>
#include "utils.h"
#include "atomic_ops.h"

#define ____cacheline_aligned  __attribute__ ((aligned (CACHE_LINE_SIZE)))

/* setting of the back-off based on the length of the queue */
#define QSPINMCS_BASE_WAIT 512
#define QSPINMCS_MAX_WAIT  4095
#define QSPINMCS_WAIT_NEXT 128

#define QSPINMCS_ON_TW0_CLS 0	/* Put the head and the tail on separate 
                               cache lines (O: not, 1: do)*/
typedef struct qspinmcslock_t 
{
	struct qspinmcslock_t *next;
	struct qspinmcslock_t *tail;
	int status;
} qspinmcslock_t ____cacheline_aligned;


int qspinmcs_trylock(qspinmcslock_t* lock);
void qspinmcs_acquire(qspinmcslock_t* lock);
void qspinmcs_release(qspinmcslock_t* lock);
int is_free_qspinmcs(qspinmcslock_t* t);

int create_qspinmcslock(qspinmcslock_t* the_lock);
qspinmcslock_t* init_qspinmcslocks(uint32_t num_locks);
void init_thread_qspinmcslocks(uint32_t thread_num);
void free_qspinmcslocks(qspinmcslock_t* the_locks);

#if defined(MEASURE_CONTENTION)
extern void qspinmcs_print_contention_stats(void);
double qspinmcs_avg_queue(void);
#endif	/* MEASURE_CONTENTION */

#endif


