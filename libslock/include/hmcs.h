/*
 * File: hmcs.h
 * Author: Tudor David <tudor.david@epfl.ch>
 *
 * Description: 
 *      Implementation of an HMCS lock
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Tudor David
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




#ifndef _HMCS_H_
#define _HMCS_H_

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
#include "padding.h"

#define ____cacheline_aligned  __attribute__ ( \
            (aligned (CACHE_LINE_SIZE)))

// How many local locking before release the global lock (default number in the
// paper)
#define RELEASE_THRESHOLD 100 // Same as cohort for comparison

struct hmcs_hnode;
typedef struct hmcs_qnode {
    struct hmcs_qnode *volatile next;
    char __pad[pad_to_cache_line(sizeof(struct hmcs_qnode *))];
    volatile uint64_t status ____cacheline_aligned;
    char __pad2[pad_to_cache_line(sizeof(uint64_t))];
    struct hmcs_hnode *last_local ____cacheline_aligned;
} hmcs_qnode_t ____cacheline_aligned;

typedef struct hmcs_hnode {
    struct hmcs_hnode *parent ____cacheline_aligned;
    struct hmcs_qnode *volatile tail;
    char __pad[pad_to_cache_line(sizeof(struct hmcs_qnode *) +
                                 sizeof(struct hmcs_hnode *))];
    hmcs_qnode_t node;
} hmcs_hnode_t ____cacheline_aligned;

typedef struct hmcs_mutex {
    hmcs_hnode_t global;
    hmcs_hnode_t local[NUMBER_OF_SOCKETS];
} hmcs_mutex ____cacheline_aligned;

typedef volatile hmcs_qnode_t *hmcs_qnode_ptr;
typedef volatile hmcs_mutex *hmcs_lock; //initialized to NULL

typedef hmcs_qnode_t* hmcs_local_params;

typedef struct hmcs_global_params {
    hmcs_lock* the_lock;
#ifdef ADD_PADDING
    uint8_t padding[CACHE_LINE_SIZE - 8];
#endif
} hmcs_global_params;


/*
   Methods for easy lock array manipulation
   */

hmcs_global_params* init_hmcs_array_global(uint32_t num_locks);

hmcs_qnode_t **init_hmcs_array_local(uint32_t thread_num, uint32_t num_locks,
                                     hmcs_global_params *the_locks);

void end_hmcs_array_local(hmcs_qnode_t **the_qnodes, uint32_t size);

void end_hmcs_array_global(hmcs_global_params* the_locks, uint32_t size);
/*
   single lock manipulation
   */

int init_hmcs_global(hmcs_global_params* the_lock);

int init_hmcs_local(uint32_t thread_num, hmcs_global_params *the_lock,
                    hmcs_qnode_t **local_data);

void end_hmcs_local(hmcs_qnode_t* the_qnodes);

void end_hmcs_global(hmcs_global_params the_locks);

/*
 *  Acquire and release methods
 */

void hmcs_acquire(hmcs_lock *the_lock, hmcs_qnode_ptr I);

void hmcs_release(hmcs_lock *the_lock, hmcs_qnode_ptr I);

int is_free_hmcs(hmcs_lock *L );

int hmcs_trylock(hmcs_lock *L, hmcs_qnode_ptr I);
#endif
