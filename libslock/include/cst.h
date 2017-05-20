/*
 * File: cst.h
 * Author: Sanidhya Kashyap <sanidya@gatech.edu>
 *         Changwoo Min <changwoo@gatech.edu>
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Sanidhya Kashyap, Changwoo Min
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


#ifndef _cst_H_
#define _cst_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#  include <numa.h>
#include <pthread.h>
#include "utils.h"
#include "atomic_ops.h"
#include "padding.h"
#include <stdint.h>

#define ____cacheline_aligned  __attribute__ ((aligned (CACHE_LINE_SIZE)))

/**
 * Timestamp + cpu and numa node info that we can get with rdtscp()
 */
struct nid_clock_info {
    uint32_t nid;
    uint64_t timestamp;
#ifdef DEBUG
	int32_t cid;
#endif
};

/**
 * linux-like circular list manipulation
 */
struct list_head {
	volatile struct list_head *next;
};

/**
 * mutex structure
 */
/* associated spin time during the traversal */
#define DEFAULT_SPIN_TIME          (1 << 15) /* max cost to put back to rq */
#define DEFAULT_HOLDER_SPIN_TIME   (DEFAULT_SPIN_TIME)
#define DEFAULT_WAITER_SPIN_TIME   (DEFAULT_SPIN_TIME)
#define DEFAULT_WAITER_WAKEUP_TIME (DEFAULT_SPIN_TIME)
/* This is an approximation */
#define CYCLES_TO_COUNTERS(v)      (v / (1U << 4))

#define NUMA_GID_BITS               (4)  /* even = empty, odd = not empty */
#define NUMA_GID_SHIFT(_n)          ((_n) * NUMA_GID_BITS)
#define NUMA_MAX_DOMAINS            (64 / NUMA_GEN_ID_BITS)
#define NUMA_NID_MASK(_n)           ((0xF) << NUMA_GID_SHIFT(_n))
#define NUMA_GID_MASK(_n, _g)       (((_g) & (0xF)) << NUMA_GID_SHIFT(_n))
#define numa_gid_inc(_gid)          (((_gid) & ~0x1) + 2)
#define numa_gid_not_empty(_gid)    ((_gid) & 0x1)

#define NUMA_BATCH_SIZE             (128) /* per numa throughput */
#define NUMA_WAITING_SPINNERS       (4) /* spinners in the waiter spin phase */

/* lock status */
#define STATE_PARKED (0)
#define STATE_LOCKED (1)

/* this will be around 8 milliseconds which is huge!!! */
#define MAX_SPIN_THRESHOLD          (1U << 20)
/* this is the cost of a getpriority syscall. */
#define MIN_SPIN_THRESHOLD          (1U << 7)

struct snode {
    /*
     * ONE CACHELINE
     * ticket info
     */
    /* current serving ticket value */
    volatile int32_t now_serving;
    /* next ticket value for the waiter */
    volatile int32_t next_ticket;
    /* batching inside the socket */
    volatile uint32_t lock_granted;
    /* batch count */
    int32_t num_proc; /* #batched processes */

    /*
     * ANOTHER CACHELINE
     * tail management
     */
    /* MCS tail to know who is the next waiter */
    struct snode *gnext ____cacheline_aligned;

    /*
     * ANOTHER CACHELINE
     * snode bookeeping for various uses
     */

    /* list node like Linux list */
    struct list_head numa_node ____cacheline_aligned;
    /* status update of the waiter */
    volatile int32_t status;
    /* node id */
    int32_t nid; /* alive: > 0 | zombie: < 0 */
    /* epoch to be used for the zombie */
    uint32_t epoch;

    /* other bookeeping stuff */
    uint32_t holder_spin_time;
    uint32_t waiter_spin_time;
    uint32_t waiter_wakeup_time;
    uint32_t task_priority;

#ifdef DEBUG
	int32_t 	cid;
#endif
} ____cacheline_aligned;

struct numa_head {
    struct list_head head;
};

typedef struct cstlock_t {
    /* snode which holds the hold */
    volatile struct snode *serving_socket;
    /* tail for the MCS style */
    volatile struct snode *gtail;
    /* Fancy way to allocate the snode */
    volatile uint64_t ngid_vec;

    /* Maintain the snode list that tells how many sockets are active */
    struct numa_head numa_list;
} cstlock_t;

int cst_trylock(cstlock_t* lock);
void cstlock_acquire(cstlock_t* lock);
void cstlock_release(cstlock_t* lock);
int is_free_cst(cstlock_t* t);

int create_cstlock(cstlock_t* the_lock);
cstlock_t* init_cstlocks(uint32_t num_locks);
void init_thread_cstlocks(uint32_t thread_num);
void free_cstlocks(cstlock_t* the_locks);

#endif
