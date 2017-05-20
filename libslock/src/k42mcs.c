/*
 * File: k42mcs.c
 * Author: Sanidhya Kashyap <sanidya@gatech.edu>
 *         Changwoo Min <changwoo@gatech.edu>
 *
 * Description:
 *      An implementation of a k42mcs lock with:
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

#include "k42mcs.h"

/* enable measure contantion to collect statistics about the 
   average queuing per lock acquisition */
#if defined(MEASURE_CONTENTION)
__thread uint64_t k42mcs_queued_total = 0;
__thread uint64_t k42mcs_acquires = 0;
#endif

#define STATE_PARKED 0
#define STATE_LOCKED 1

#define smp_swap(__ptr, __val)                                                 \
	__sync_lock_test_and_set(__ptr, __val)
#define smp_cas(__ptr, __oval, __nval)                                         \
	__sync_bool_compare_and_swap(__ptr, __oval, __nval)
#define smp_faa(__ptr, __val)                                                  \
	__sync_fetch_and_add(__ptr, __val)

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

static inline void barrier(void)
{
	__asm__ __volatile__("":::"memory");
}


int k42mcs_trylock(k42mcslock_t* lock) 
{
	if (smp_cas(&lock->tail, NULL, &lock->next))
		return 0;

	return 1;
}

void
k42mcs_acquire(k42mcslock_t* lock)
{
	k42mcslock_t cur_qnode;
	k42mcslock_t *prev_qnode, *next_qnode;
	cur_qnode.next = NULL;
	cur_qnode.status = STATE_PARKED;

	prev_qnode = smp_swap(&lock->tail, &cur_qnode);
	if (prev_qnode) {
#if 1
		cur_qnode.tail = lock;

		barrier();
		prev_qnode->next = &cur_qnode;
		barrier();

		while(cur_qnode.tail)
			smp_rmb();
#endif
#if 0
		barrier();
		prev_qnode->next = &cur_qnode;
		barrier();

		while(cur_qnode.status == STATE_PARKED)
			smp_rmb();
#endif
	}

	next_qnode = cur_qnode.next;
	if (!next_qnode) {
		barrier();
		lock->next = NULL;
		if (!smp_cas(&lock->tail, &cur_qnode, &lock->next)) {
			while(!cur_qnode.next)
				smp_rmb();

			lock->next = cur_qnode.next;
		}
	} else
		lock->next = next_qnode;
}

void
k42mcs_release(k42mcslock_t* lock)
{
	k42mcslock_t *next_qnode = lock->next;

	barrier();
	if (!next_qnode) {
		if (smp_cas(&lock->tail, &lock->next, NULL))
			return;

		while(!lock->next)
			smp_rmb();
		next_qnode = lock->next;
	}
#if 1
	next_qnode->tail = NULL;
#endif
#if 0
	next_qnode->status = STATE_LOCKED;
#endif
	smp_wmb();
}


int create_k42mcslock(k42mcslock_t* the_lock) 
{
	the_lock->next = NULL;
	the_lock->tail = NULL;
	MEM_BARRIER;
	return 0;
}


int is_free_k42mcs(k42mcslock_t* t)
{
	if (t->tail == NULL) {
		return 1;
	}
	return 0;
}

void init_thread_k42mcslocks(uint32_t thread_num) 
{
	set_cpu(thread_num);
}

k42mcslock_t* 
init_k42mcslocks(uint32_t num_locks) 
{
	k42mcslock_t* the_locks;
	the_locks = (k42mcslock_t*) malloc(num_locks * sizeof(k42mcslock_t));
	uint32_t i;
	for (i = 0; i < num_locks; i++) 
	{
		the_locks[i].status = 0;
		the_locks[i].next = NULL;
		the_locks[i].tail = NULL;
	}
	MEM_BARRIER;
	return the_locks;
}

void
free_k42mcslocks(k42mcslock_t* the_locks) 
{
	free(the_locks);
}


#if defined(MEASURE_CONTENTION)
void
k42mcs_print_contention_stats()
{
	printf("#Acquires: %10llu / #Total queuing: %10llu / Avg. queuing: %.3f\n",
	       (long long unsigned) k42mcs_acquires, (long long unsigned) k42mcs_queued_total, avg_q);
}

double
k42mcs_avg_queue()
{
	double avg_q = k42mcs_queued_total / (double) k42mcs_acquires;
	return avg_q;
}

#endif	/* MEASURE_CONTENTION */
