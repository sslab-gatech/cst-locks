/*
 * File: cstmcsvar.h
 * Author: Sanidhya Kashyap <sanidhya@gatech.edu>
 *         Changwoo Min <changwoo@gatech.edu>
 *
 * Description:
 *      Implementation of an CSTMCSVAR lock
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Sanidhya Kashyap, Changwoo Min
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




#ifndef _CSTMCSVAR_H_
#define _CSTMCSVAR_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#ifndef __sparc__
#include <numa.h>
#endif
#include <pthread.h>
#include "utils.h"
#include "atomic_ops.h"
#include <assert.h>

#define ____cacheline_aligned  __attribute__ ((aligned (CACHE_LINE_SIZE)))

enum {
	false,
	true,
};
/**
 * Timestamp + cpu and numa node info that we can get with rdtscp()
 */
struct nid_clock_info {
	uint64_t timestamp;
	uint32_t nid;
	int32_t cid;
};

/**
 * linux-like circular list manipulation
 */
struct list_head {
	volatile struct list_head *next;
	volatile struct list_head *prev;
};


/**
 * mutex structure
 */
/* associated spin time during the traversal */
#define DEFAULT_SPIN_TIME          (1 << 15) /* max cost to put back to rq */
#define DEFAULT_HOLDER_SPIN_TIME   (DEFAULT_SPIN_TIME)
#define DEFAULT_WAITER_SPIN_TIME   (DEFAULT_SPIN_TIME)
#define DEFAULT_WAITER_WAKEUP_TIME (DEFAULT_SPIN_TIME)

#define NUMA_GID_BITS               (4)  /* even = empty, odd = not empty */
#define NUMA_GID_SHIFT(_n)          ((_n) * NUMA_GID_BITS)
#define NUMA_MAX_DOMAINS            (64 / NUMA_GEN_ID_BITS)
#define NUMA_NID_MASK(_n)           ((0xF) << NUMA_GID_SHIFT(_n))
#define NUMA_GID_MASK(_n, _g)       (((_g) & (0xF)) << NUMA_GID_SHIFT(_n))
#define numa_gid_inc(_gid)          (((_gid) & ~0x1) + 2)
#define numa_gid_not_empty(_gid)    ((_gid) & 0x1)


/* lock status */
#define STATE_PARKED (0)
#define STATE_LOCKED (1)

/* this will be around 8 milliseconds which is huge!!! */
#define MAX_SPIN_THRESHOLD          (1U << 20)
/* this is the cost of a getpriority syscall. */
#define MIN_SPIN_THRESHOLD          (1U << 7)

#define NUMA_BATCH_SIZE             (128) /* per numa throughput */
#define PARKING_BITS 	32
#define COHORT_START    1
#define ACQUIRE_PARENT  ((1ULL << (PARKING_BITS)) - 4)
#define WAIT            (ACQUIRE_PARENT + 2)
#define REQUEUE		(ACQUIRE_PARENT + 3)

#define UNPARKED 	0ULL
#define PARKED 		1ULL
#define RESET_UNPARKED 	2ULL
#define VERY_NEXT 	3ULL

#define PARKING_STATE(n) 	((n) >> (PARKING_BITS))
#define LOCKING_STATE(n) 	((n) & (0xffffffff))
#define PARKING_STATE_MASK(n) 	((n) << (PARKING_BITS))
#define UNPARKED_WAITER_STATE 	((PARKING_STATE_MASK(UNPARKED)) | (WAIT))
#define PARKED_WAITER_STATE 	((PARKING_STATE_MASK(PARKED)) | (WAIT))
#define VNEXT_WAITER_STATE 	((PARKING_STATE_MASK(VERY_NEXT)) | (WAIT))
#define REQUEUE_WAITER_STATE 	((PARKING_STATE_MASK(RESET_UNPARKED)) | (WAIT))
#define qnode_lock_state(q)	LOCKING_STATE(((q)->status))
#define qnode_park_state(q)	PARKING_STATE(((q)->status))

#define QNODE_UNPARKED		0
#define QNODE_REQUEUE		1
#define QNODE_LOCK_ACQUIRD	2

#ifndef __KERNEL__
#define spinlock_t             pthread_spinlock_t
#define spin_lock(l)           pthread_spin_lock(l)
#define spin_trylock(l)        pthread_spin_trylock(l)
#define spin_unlock(l)         pthread_spin_unlock(l)
#define spinlock_init(l)       pthread_spin_init((l), PTHREAD_PROCESS_PRIVATE)
#define spinlock_destroy(l)    pthread_spin_destroy(l)
#else
#define spinlock_destroy(l)    do { } while(0)
#endif

struct snode;
typedef struct qnode {
	volatile struct qnode *next;

	volatile uint64_t status ____cacheline_aligned;
	int cid;
	struct list_head wait_node;
	int in_list;
	struct snode *my_snode;
} cstmcsvar_qnode ____cacheline_aligned;

struct cst_t;
struct snode {
	/*
	 * ONE CACHELINE
	 */
	volatile struct qnode *qnext;
	volatile struct qnode *qtail;
	/* batch count */
	int32_t num_proc; /* #batched processes */

	/*
	 * ANOTHER CACHELINE
	 * tail management
	 */
	/* MCS tail to know who is the next waiter */
	volatile struct snode *gnext ____cacheline_aligned;
	/* status update of the waiter */
	volatile int32_t status;

	/*
	 * snode bookeeping for various uses
	 */
	/* list node like Linux list */
	struct list_head numa_node;
	/* node id */
	int32_t nid; /* alive: > 0 | zombie: < 0 */

	spinlock_t wait_lock;
	struct list_head wait_list;

	struct cst_t *my_lock;

#ifdef CST_DEBUG
	int32_t 	cid;
#endif
} ____cacheline_aligned;

struct numa_head {
	struct list_head head;
};

typedef struct cst_t {
	/* snode which holds the hold */
	volatile struct snode *serving_socket;
	/* tail for the MCS style */
	volatile struct snode *gtail;
	/* Fancy way to allocate the snode */
	volatile uint64_t ngid_vec;

	/* Maintain the snode list that tells how many sockets are active */
	struct numa_head numa_list;
} cstmcsvar_mutex_t ____cacheline_aligned;


typedef volatile cstmcsvar_qnode *cstmcsvar_qnode_ptr;
typedef volatile cstmcsvar_mutex_t cstmcsvar_lock; //initialized to NULL

typedef cstmcsvar_qnode* cstmcsvar_local_params;

typedef struct cstmcsvar_global_params {
	cstmcsvar_mutex_t *the_lock;
} cstmcsvar_global_params;


/*
   Methods for easy lock array manipulation
   */

cstmcsvar_global_params* init_cstmcsvar_array_global(uint32_t num_locks);

cstmcsvar_qnode** init_cstmcsvar_array_local(uint32_t thread_num, uint32_t num_locks);

void end_cstmcsvar_array_local(cstmcsvar_qnode** the_qnodes, uint32_t size);

void end_cstmcsvar_array_global(cstmcsvar_global_params* the_locks, uint32_t size);
/*
   single lock manipulation
   */

int init_cstmcsvar_global(cstmcsvar_global_params* the_lock);

int init_cstmcsvar_local(uint32_t thread_num, cstmcsvar_qnode** the_qnode);

void end_cstmcsvar_local(cstmcsvar_qnode* the_qnodes);

void end_cstmcsvar_global(cstmcsvar_global_params the_locks);

/*
 *  Acquire and release methods
 */

void cstmcsvar_acquire(cstmcsvar_lock *the_lock, cstmcsvar_qnode_ptr I);

void cstmcsvar_release(cstmcsvar_lock *the_lock, cstmcsvar_qnode_ptr I);

int is_free_cstmcsvar(cstmcsvar_lock *L );

int cstmcsvar_trylock(cstmcsvar_lock *L, cstmcsvar_qnode_ptr I);
#endif
