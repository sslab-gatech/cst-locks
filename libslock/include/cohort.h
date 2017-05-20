/*
 * File: cohort.h
 * Author: Sanidhya Kashyap <sanidhya@gatech.edu>
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


#ifndef _cohort_H_
#define _cohort_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <numa.h>
#include <pthread.h>
#include "utils.h"
#include "atomic_ops.h"
#include "padding.h"

#define BATCH_COUNT 100
#define PTL_SLOTS NUMBER_OF_SOCKETS

/* setting of the back-off based on the length of the queue */
#define ____cacheline_aligned  __attribute__ ( \
                (aligned (CACHE_LINE_SIZE)))

typedef struct cohort_lock
{
    // Use union for compare and swap
    union {
        volatile uint64_t u;
        struct {
            volatile uint32_t grant;
            volatile uint32_t request;
        } s;
    } u __attribute__((aligned(CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint32_t) + sizeof(uint32_t))];
    volatile uint32_t top_grant;
    int32_t batch_count;

} tkt_lock_t ____cacheline_aligned;

struct grant_slot {
    volatile uint32_t grant;
    char __pad[pad_to_cache_line(sizeof(uint32_t))];
} ____cacheline_aligned;

typedef struct partitioned_cohort_lock {
    volatile uint32_t request;
    volatile uint32_t owner_ticket;
    char __pad[pad_to_cache_line(sizeof(uint32_t) + sizeof(uint32_t))];
    // Each slot is cache align, the purpose of PLT is avoid cache line
    // transfers
    struct grant_slot grants[PTL_SLOTS];
} ptl_lock_t ____cacheline_aligned;

typedef struct c_ptl_tkt {
    ptl_lock_t top_lock;
    tkt_lock_t local_locks[NUMBER_OF_SOCKETS];
    tkt_lock_t *volatile top_home;
} cohortlock_t ____cacheline_aligned;


int cohort_trylock(cohortlock_t* lock);
void cohortlock_acquire(cohortlock_t* lock);
void cohortlock_release(cohortlock_t* lock);
int is_free_cohort(cohortlock_t* t);

int create_cohortlock(cohortlock_t* the_lock);
cohortlock_t* init_cohortlocks(uint32_t num_locks);
void init_thread_cohortlocks(uint32_t thread_num);
void free_cohortlocks(cohortlock_t* the_locks);

#if defined(MEASURE_CONTENTION)
extern void cohort_print_contention_stats(void);
double cohort_avg_queue(void);
#endif	/* MEASURE_CONTENTION */

#endif
