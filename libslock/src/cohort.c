/*
 * File: cohort.c
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
 * lockIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "cohort.h"

/* enable measure contantion to collect statistics about the 
   average queuing per lock acquisition */
#if defined(MEASURE_CONTENTION)
__thread uint64_t cohort_queued_total = 0;
__thread uint64_t cohort_acquires = 0;
#endif

static inline void smp_mb(void)
{
    __asm__ __volatile__("mfence":::"memory");
}

static inline void smp_rmb(void)
{
    __asm__ __volatile__("lfence":::"memory");
}

static inline void smp_wmb(void)
{
    __asm__ __volatile__("sfence":::"memory");
}

static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CORES_PER_SOCKET);
}

static inline void CPU_PAUSE(void)
{
    asm volatile("pause":::"memory");
}

int
cohort_trylock(cohortlock_t* lock)
{
    tkt_lock_t *local_lock = &lock->local_locks[current_numa_node()];
    uint32_t t = 0;

    // Trylock the local lock
    uint32_t me     = local_lock->u.s.request;
    uint32_t menew  = me + 1;
    uint64_t cmp    = ((uint64_t)me << 32) + me;
    uint64_t cmpnew = ((uint64_t)menew << 32) + me;

#if 0
	atomic_count++;
#endif
    if (__sync_val_compare_and_swap(&local_lock->u.u, cmp, cmpnew) != cmp)
        return 1;

    // Do we already have the local lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        return 0;
    }

    /**
     * It is not possible to lockement a true trylock with partitioned ticket
     * lock.
     * As the partitioned provides cohort detection, we can watch if there is
     * anyone else, and if not try a blocking lock
     **/
    if (lock->top_lock.grants[lock->top_lock.request % PTL_SLOTS].grant !=
        lock->top_lock.request) {
        // Lock not available, release the local lock
        local_lock->u.s.grant++;
        return 1;
    } else {
        /**
         * If the lock is abortable, we can try a few times and abort.
         * But partitioned ticket lock is not abortable, so we might potentially
         * wait (this seems the best we can do).
         **/
#if 0
		atomic_count++;
#endif
        t = __sync_fetch_and_add(&lock->top_lock.request, 1);
        while (lock->top_lock.grants[t % PTL_SLOTS].grant != t)
            CPU_PAUSE();
    }

    lock->top_lock.owner_ticket = t;
    lock->top_home              = local_lock;

    return 0;
}

void
cohortlock_acquire(cohortlock_t* lock)
{
    tkt_lock_t *local_lock = &lock->local_locks[current_numa_node()];

    // Acquire the local lock
#if 0
	atomic_count++;
#endif
    int t = __sync_fetch_and_add(&local_lock->u.s.request, 1);
    while (local_lock->u.s.grant != t)
        CPU_PAUSE();

    // Do we already have the local lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        return;
    }

    // Acquire top lock
#if 0
	atomic_count++;
#endif
    t = __sync_fetch_and_add(&lock->top_lock.request, 1);
    while (lock->top_lock.grants[t % PTL_SLOTS].grant != t)
        CPU_PAUSE();

    lock->top_lock.owner_ticket = t;
    lock->top_home              = local_lock;
}

void
cohortlock_release(cohortlock_t* lock) 
{
    tkt_lock_t *local_lock = lock->top_home;
    int new_grant          = local_lock->u.s.grant + 1;

#if 0
	release_count++;
	if (release_count % 10240 == 0)
		fprintf(stderr, "count: %lu, atomic: %lu\n", release_count, atomic_count);
#endif
    // Is anybody there?
    if (local_lock->u.s.request != new_grant) {
        // Cohort detection
        local_lock->batch_count--;
        // Give the lock to a thread on the same node
        if (local_lock->batch_count >= 0) {
            local_lock->top_grant = 1;
            smp_wmb();
            local_lock->u.s.grant = new_grant;
            return;
        }
        local_lock->batch_count = BATCH_COUNT;
    }

    // Release the local lock AND the global lock
    int new_owner_ticket = lock->top_lock.owner_ticket + 1;
	smp_wmb();
    lock->top_lock.grants[new_owner_ticket % PTL_SLOTS].grant =
        new_owner_ticket;
    local_lock->u.s.grant = new_grant;
}


int create_cohortlock(cohortlock_t* the_lock) 
{
    memset(the_lock, 0, sizeof(*the_lock));
    smp_wmb();
    return 0;
}


int is_free_cohort(cohortlock_t* t)
{
    tkt_lock_t *local_lock = &t->local_locks[current_numa_node()];

    // Trylock the local lock
    uint32_t me     = local_lock->u.s.request;
    uint32_t menew  = me + 1;
    uint64_t cmp    = ((uint64_t)me << 32) + me;
    uint64_t cmpnew = ((uint64_t)menew << 32) + me;

#if 0
	atomic_count++;
#endif
    if (__sync_val_compare_and_swap(&local_lock->u.u, cmp, cmpnew) != cmp)
        return 1;

    // Do we already have the local lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        smp_rmb();
        return 0;
    }
    return 1;
}

void init_thread_cohortlocks(uint32_t thread_num) 
{
  set_cpu(thread_num);
}

cohortlock_t* 
init_cohortlocks(uint32_t num_locks) 
{
    cohortlock_t *the_lock;

    the_lock = (cohortlock_t *)malloc(num_locks * sizeof(cohortlock_t));
    memset(the_lock, 0, num_locks * sizeof(cohortlock_t));
    return the_lock;
}

void
free_cohortlocks(cohortlock_t* the_locks) 
{
  free(the_locks);
}


#if defined(MEASURE_CONTENTION)
void
cohort_print_contention_stats()
{
  double avg_q = cohort_queued_total / (double) cohort_acquires;
  printf("#Acquires: %10llu / #Total queuing: %10llu / Avg. queuing: %.3f\n",
	 (long long unsigned) cohort_acquires, (long long unsigned) cohort_queued_total, avg_q);
}

double
cohort_avg_queue()
{
  double avg_q = cohort_queued_total / (double) cohort_acquires;
  return avg_q;
}

#endif	/* MEASURE_CONTENTION */
