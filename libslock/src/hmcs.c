/*
 * File: hmcs.c
 * Author: Tudor David <tudor.david@epfl.ch>
 *
 * Description: 
 *      HMCS lock implementation
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




#include "hmcs.h"

#define COHORT_START 1
#define ACQUIRE_PARENT (UINT64_MAX - 1)
#define WAIT UINT64_MAX
#define UNLOCKED 0
#define LOCKED 1

#define MEMORY_BARRIER() __sync_synchronize()
#define CBARRIER() asm volatile("" : : : "memory")

static inline void CPU_PAUSE(void)
{
    asm volatile("pause":::"memory");
}

static inline void *xchg_64(void *ptr, void *x)
{
	__asm__ __volatile__("xchgq %0,%1"
						 : "=r"((unsigned long long)x)
						 : "m"(*(volatile long long *)ptr),
						 "0"((unsigned long long)x)
						 : "memory");

	return x;
}

static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CORES_PER_SOCKET);
}

static inline int __hmcs_mutex_global_lock(hmcs_hnode_t *impl,
                                           hmcs_qnode_t *me)
{
    hmcs_qnode_t *tail;

    me->next   = 0;
    me->status = LOCKED;

    tail = xchg_64((void *)&impl->tail, (void *)me);

    /* No one there? */
    if (!tail) {
        me->status = UNLOCKED;
        return 0;
    }

    /* Someone there, need to link in */
    CBARRIER();
    tail->next = me;

    while (me->status == LOCKED)
        CPU_PAUSE();
    return 0;
}

static inline int __hmcs_mutex_local_lock(hmcs_hnode_t *impl,
                                          hmcs_qnode_t *me)
{
    hmcs_qnode_t *tail;

    // Prepare the node for use
    me->next   = 0;
    me->status = WAIT;

    // printf("[%2d] Enqueing %p on %p\n", cur_thread_id, me);
    tail = xchg_64((void *)&impl->tail, (void *)me);

    if (tail) {
        tail->next = me;
        uint64_t cur_status;

        CBARRIER();
        while ((cur_status = me->status) == WAIT)
            CPU_PAUSE();

        // Acquired, enter CS
        if (cur_status < ACQUIRE_PARENT) {
            return 0;
        }
    }

    me->status = COHORT_START;
    int ret    = __hmcs_mutex_global_lock(impl->parent, &impl->node);
    return ret;
}

static inline void __hmcs_release_helper(hmcs_hnode_t *impl, hmcs_qnode_t *me,
                                         uint64_t val)
{
    /* No successor yet? */
    if (!me->next) {
        /* Try to atomically unlock */
        if (__sync_val_compare_and_swap(&impl->tail, me, 0) == me)
            return;

        /* Wait for successor to appear */
        while (!me->next)
            CPU_PAUSE();
    }

    // Pass lock
    me->next->status = val;
    MEMORY_BARRIER();
}

static inline int __hmcs_mutex_global_trylock(hmcs_hnode_t *impl,
                                              hmcs_qnode_t *me)
{
    hmcs_qnode_t *tail;

    me->next   = 0;
    me->status = LOCKED;

    tail = __sync_val_compare_and_swap(&impl->tail, NULL, me);
    if (tail == NULL) {
        me->status = UNLOCKED;
        return 0;
    }

    return EBUSY;
}

static inline int __hmcs_mutex_local_trylock(hmcs_hnode_t *impl,
                                             hmcs_qnode_t *me)
{
    hmcs_qnode_t *tail;

    // Prepare the node for use
    me->next   = 0;
    me->status = WAIT;

    tail = __sync_val_compare_and_swap(&impl->tail, NULL, me);

    if (tail != NULL) {
        return EBUSY;
    }

    me->status = COHORT_START;
    int ret    = __hmcs_mutex_global_trylock(impl->parent, &impl->node);

    // Unable to get the global, release the local and fail
    if (ret == EBUSY) {
        // Unlock and ask the successor to get the global lock if it is here
        __hmcs_release_helper(impl, me, ACQUIRE_PARENT);
    }

    return ret;
}

static inline int __hmcs_mutex_global_unlock(hmcs_hnode_t *impl,
                                             hmcs_qnode_t *me)
{
    __hmcs_release_helper(impl, me, UNLOCKED);
    return 0;
}

static inline int __hmcs_mutex_local_unlock(hmcs_hnode_t *impl,
                                            hmcs_qnode_t *me)
{
    uint64_t cur_count = me->status;

    // Lower level release
    if (cur_count == RELEASE_THRESHOLD) {
        // Reached threshold, release the next level (suppose 2-level)
        __hmcs_mutex_global_unlock(impl->parent, &impl->node);

        // Ask successor to acquire next-level lock
        __hmcs_release_helper(impl, me, ACQUIRE_PARENT);
        return 0;
    }

    // Not reached threshold
    hmcs_qnode_t *succ = me->next;
    if (succ) {
        succ->status = cur_count + 1;
        return 0;
    }

    // No known successor, release to parent
    __hmcs_mutex_global_unlock(impl->parent, &impl->node);

    // Ask successor to acquire next-level lock
    __hmcs_release_helper(impl, me, ACQUIRE_PARENT);
    return 0;
}


int hmcs_trylock(hmcs_lock *L, hmcs_qnode_ptr I)
{
    hmcs_mutex *l = (hmcs_mutex *)L;
    hmcs_hnode_t *local = &l->local[current_numa_node()];

    // Must remember the last local node for release
    I->last_local = local;

    int ret = __hmcs_mutex_local_trylock(local, (hmcs_qnode_t *)I);
    return ret;
}

void hmcs_acquire(hmcs_lock *L, hmcs_qnode_ptr I)
{
    hmcs_mutex *l = (hmcs_mutex *)L;
    hmcs_hnode_t *local = &l->local[current_numa_node()];

    // Must remember the last local node for release
    I->last_local = local;

    __hmcs_mutex_local_lock(local, (hmcs_qnode_t *)I);
}

void hmcs_release(hmcs_lock *L, hmcs_qnode_ptr I)
{
    __hmcs_mutex_local_unlock(I->last_local, (hmcs_qnode_t *)I);
}

int is_free_hmcs(hmcs_lock *L )
{
    if ((*L) == NULL) return 1;
    return 0;
}

/*
   Methods for easy lock array manipulation
   */

hmcs_global_params* init_hmcs_array_global(uint32_t num_locks)
{
    uint32_t i, j;
    hmcs_global_params* the_locks = (hmcs_global_params *)malloc(num_locks *
                                                  sizeof(hmcs_global_params));
    hmcs_mutex *the_lock;
    for (i=0;i<num_locks;i++) {
        the_locks[i].the_lock=(hmcs_lock*)malloc(sizeof(hmcs_lock));
        memset(&the_locks[i].the_lock, 0, sizeof(the_locks[i].the_lock));
        the_lock = (the_locks[i].the_lock);
        for (j = 0; j < NUMBER_OF_SOCKETS; ++j) {
            the_lock->local[j].parent = &the_lock->global;
            the_lock->local[j].tail = NULL;
        }
        the_lock->global.parent = NULL;
        the_lock->global.tail = NULL;
    }
    MEM_BARRIER;
    return the_locks;
}


hmcs_qnode_t** init_hmcs_array_local(uint32_t thread_num, uint32_t num_locks,
                                     hmcs_global_params *the_locks)
{
    set_cpu(thread_num);

    //init its qnodes
    uint32_t i;
    hmcs_qnode_t** the_qnodes = (hmcs_qnode_t **)malloc(num_locks *
                                                 sizeof(hmcs_qnode_t *));
    for (i=0;i<num_locks;i++) {
        the_qnodes[i]=(hmcs_qnode_t *)malloc(sizeof(hmcs_qnode_t));
    }
    MEM_BARRIER;
    return the_qnodes;

}

void end_hmcs_array_local(hmcs_qnode_t** the_qnodes, uint32_t size)
{
    uint32_t i;
    for (i = 0; i < size; i++) {
        free(the_qnodes[i]);
    }
    free(the_qnodes);
}

void end_hmcs_array_global(hmcs_global_params* the_locks, uint32_t size)
{
    uint32_t i;
    for (i = 0; i < size; i++) {
        free(the_locks[i].the_lock);
    }
    free(the_locks);
}

int init_hmcs_global(hmcs_global_params* the_lock)
{
    int i;
    hmcs_mutex *l;
    the_lock->the_lock=(hmcs_lock*)malloc(sizeof(hmcs_lock));
    l = (the_lock->the_lock);
    for (i = 0; i < NUMBER_OF_SOCKETS; ++i) {
       l->local[i].parent = &l->global;
       l->local[i].tail = NULL;
    }
    l->global.parent = NULL;
    l->global.tail = NULL;
    MEM_BARRIER;
    return 0;
}


int init_hmcs_local(uint32_t thread_num, hmcs_global_params *the_lock,
                    hmcs_qnode_t **local_data)
{
    set_cpu(thread_num);

    (*local_data)=(hmcs_qnode_t*)malloc(sizeof(hmcs_qnode_t));
    MEM_BARRIER;
    return 0;
}

void end_hmcs_local(hmcs_qnode_t* the_qnodes)
{
    free(the_qnodes);
}

void end_hmcs_global(hmcs_global_params the_locks)
{
    free(the_locks.the_lock);
}
