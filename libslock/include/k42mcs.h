/*
 * File: k42mcs.h
 * Author: Sanidhya Kashyap <sanidhya@gatech.edu>
 *
 * Description:
 *      An implementation of a k42mcs lock
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Sanidhya Kashyap
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


#ifndef _K42MCS_H_
#define _K42MCS_H_

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
#define K42MCS_BASE_WAIT 512
#define K42MCS_MAX_WAIT  4095
#define K42MCS_WAIT_NEXT 128

#define K42MCS_ON_TW0_CLS 0	/* Put the head and the tail on separate 
                               cache lines (O: not, 1: do)*/
typedef struct k42mcslock_t 
{
	struct k42mcslock_t *next;
	struct k42mcslock_t *tail;
	int status;
} k42mcslock_t ____cacheline_aligned;


int k42mcs_trylock(k42mcslock_t* lock);
void k42mcs_acquire(k42mcslock_t* lock);
void k42mcs_release(k42mcslock_t* lock);
int is_free_k42mcs(k42mcslock_t* t);

int create_k42mcslock(k42mcslock_t* the_lock);
k42mcslock_t* init_k42mcslocks(uint32_t num_locks);
void init_thread_k42mcslocks(uint32_t thread_num);
void free_k42mcslocks(k42mcslock_t* the_locks);

#if defined(MEASURE_CONTENTION)
extern void k42mcs_print_contention_stats(void);
double k42mcs_avg_queue(void);
#endif	/* MEASURE_CONTENTION */

#endif


