/*
 * File: qspinmcs.c
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

#include "qspinmcs.h"

/* enable measure contantion to collect statistics about the 
   average queuing per lock acquisition */
#if defined(MEASURE_CONTENTION)
__thread uint64_t qspinmcs_queued_total = 0;
__thread uint64_t qspinmcs_acquires = 0;
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


int qspinmcs_trylock(qspinmcslock_t* lock) 
{
	if (smp_cas(&lock->tail, NULL, &lock->next))
		return 0;

	return 1;
}

void
qspinmcs_acquire(qspinmcslock_t* lock)
{
	qspinmcslock_t cur_qnode;
	qspinmcslock_t *prev_qnode, *next_qnode;
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
qspinmcs_release(qspinmcslock_t* lock)
{
	qspinmcslock_t *next_qnode = lock->next;

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


int create_qspinmcslock(qspinmcslock_t* the_lock) 
{
	the_lock->next = NULL;
	the_lock->tail = NULL;
	MEM_BARRIER;
	return 0;
}


int is_free_qspinmcs(qspinmcslock_t* t)
{
	if (t->tail == NULL) {
		return 1;
	}
	return 0;
}

void init_thread_qspinmcslocks(uint32_t thread_num) 
{
	set_cpu(thread_num);
}

qspinmcslock_t* 
init_qspinmcslocks(uint32_t num_locks) 
{
	qspinmcslock_t* the_locks;
	the_locks = (qspinmcslock_t*) malloc(num_locks * sizeof(qspinmcslock_t));
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
free_qspinmcslocks(qspinmcslock_t* the_locks) 
{
	free(the_locks);
}


#if defined(MEASURE_CONTENTION)
void
qspinmcs_print_contention_stats()
{
	printf("#Acquires: %10llu / #Total queuing: %10llu / Avg. queuing: %.3f\n",
	       (long long unsigned) qspinmcs_acquires, (long long unsigned) qspinmcs_queued_total, avg_q);
}

double
qspinmcs_avg_queue()
{
	double avg_q = qspinmcs_queued_total / (double) qspinmcs_acquires;
	return avg_q;
}

#endif	/* MEASURE_CONTENTION */
