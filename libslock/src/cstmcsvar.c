/*
 * File: cstmcsvar.c
 * Author: Sanidhya Kasyap <sanidhya@gatech.edu>
 *         Changwoo Min <changwoo@gatech.edu>
 *
 * Description:
 *      CSTMCSVAR lock implementation
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




#include "cstmcsvar.h"

#define PARKING

/**
 * common
 */
#define INIT_LIST_HEAD(ptr)                                                    \
	do { \
		(ptr)->next = (ptr);  \
		(ptr)->prev = (ptr);  \
	} while(0)

#define list_entry(ptr, type, member)                                          \
	({const typeof( ((type *)0)->member ) *__mptr = (ptr);                     \
	 (type *)( (char *)__mptr - offsetof(type,member) );})


#define list_for_each_entry(pos, head, member)                                 \
	for (pos = list_entry((struct list_head *)(head)->next, typeof(*pos),      \
			      member);                                             \
	     &pos->member != (head);                                               \
	     pos = list_entry((struct list_head *)pos->member.next, typeof(*pos),  \
			      member))

#define smp_swap(__ptr, __val)                                                 \
	__sync_lock_test_and_set(__ptr, __val)
#define smp_cas(__ptr, __oval, __nval)                                         \
	__sync_bool_compare_and_swap(__ptr, __oval, __nval)
#define smp_faa(__ptr, __val)                                                  \
	__sync_fetch_and_add(__ptr, __val)

#define min(a, b) ((a)<(b)?(a):(b))
#define ACCESS_ONCE(x) (*(__volatile__ __typeof__(x) *)&(x))

#ifdef CST_DEBUG
typedef enum {
	RED,
	GREEN,
	BLUE,
	MAGENTA,
	YELLOW,
	CYAN,
	END,
} color_num;

static char colors[END][8] = {
	"\x1B[31m",
	"\x1B[32m",
	"\x1B[34m",
	"\x1B[35m",
	"\x1b[33m",
	"\x1b[36m",
};
static unsigned long counter = 0;

static __thread int __tcid = -1;

#define dprintf(__fmt, ...)                                                    \
	do {                                                                       \
		smp_faa(&counter, 1);                                                  \
		fprintf(stderr, "%s [DBG:%010lu: %d (%s: %d)]: " __fmt,                \
			colors[__tcid % END], counter, __tcid,                         \
			__func__, __LINE__, ##__VA_ARGS__);                            \
	} while(0);
#define dassert(v)      assert((v))
#define NUM_RELEASES        1024
#define LOOP_MOD            100
#define declare_loop_counter(v) unsigned long (v) = 0;
#define dprintf_loop(v, __fmt, ...)                                            \
	do {                                                                       \
		if (((v) % LOOP_MOD) == 0) {                                           \
			smp_faa(&counter, 1);                                              \
			fprintf(stderr, "%s [DBG:%010lu: %d (%s: %d)]: (count: %lu) "      \
				__fmt, colors[__tcid % END], counter, __tcid,              \
				__func__, __LINE__, (v), ##__VA_ARGS__);                   \
		}                                                                      \
		++(v);                                                                 \
	} while(0)
#define update_cid(q, c)                                                       \
	do {                                                                       \
		(q)->cid = (c);                                                        \
		__tcid = (c);                                                          \
	} while (0)
#define inc_atomic_count()                                                     \
	do {                                                                       \
		smp_faa(&atomic_count, 1);                                             \
	} while(0)
#define inc_release_count()                                                    \
	do {                                                                       \
		smp_faa(&release_count, 1);                                            \
	} while(0)
#define inc_casfail_count()                                                    \
	do {                                                                       \
		smp_faa(&cas_failures, 1);                                             \
	} while(0)
#define print_accoutning()                                                     \
	do {                                                                       \
		if ((release_count % NUM_RELEASES) == 0) {                             \
			dprintf("#releases: %lu, #atomics: %lu #cas fails: %lu\n",         \
				release_count, atomic_count, cas_failures);                \
		}                                                                      \
	} while(0)

#define print_numa_list(head)                                                  \
	do {                                                                       \
		struct snode *pos;                                                     \
		dprintf(" nuam list: ");                                               \
		list_for_each_entry(pos, head, numa_node) {                            \
			fprintf(stderr, "numa: 0x%08lx, nid: %02d |--> 0x%08lx ",          \
				(uintptr_t)(struct list_head *)&pos->numa_node, pos->nid,  \
				(uintptr_t)(struct list_head *)pos->numa_node.next);       \
		}                                                                      \
		fprintf(stderr, "\n");                                                 \
	} while (0)

static uint64_t atomic_count  ____cacheline_aligned;
static uint64_t release_count ____cacheline_aligned;
static uint64_t cas_failures  ____cacheline_aligned;

#else
#define declare_loop_counter(v) do { } while(0)
#define dprintf_loop(v, __fmt, ...) do { } while(0)
#define update_cid(q, c) do { } while(0)
#define inc_atomic_count() do { } while(0)
#define inc_release_count() do { } while(0)
#define inc_casfail_count() do { } while(0)
#define dprintf(__fmt, ...) do { } while(0)
#define dassert(v)  do { } while(0)
#define print_accoutning() do { } while(0)
#define print_numa_list(head) do { } while(0)
#define print_snode_list(snode) do { } while(0)
#endif /* end of CST_DEBUG */

#ifdef MUTEX_TASK_CONTEXT
#define current                 getpid()
#define get_task_priority(p)    getpriority(PRIO_PROCESS, p)
#define set_task_priority(p, n) setpriority(PRIO_PROCESS, p, n)
#define boost_task_priority(p, n)                                              \
	do {                                                                       \
		if (n != -20)                                                          \
		set_task_priority(p, -20);                                             \
	} while (0)
#define __get_priority()        get_task_priority((current))
#define __set_priority(n)       nice(n)
#else
#define current                     (-1)
#define get_task_priority(p)        (0)
#define set_task_priority(p)        do { } while (0)
#define boost_task_priority(p,n)    do { } while (0)
#define __get_priority()            do { } while (0)
#define __set_priority(n)           do { } while (0)
#endif /* end of MUTEX_TASK_CONTEXT */

#ifdef __KERNEL__
#define get_task(v)                                                            \
	do {                                                                       \
		v->task = current;                                                     \
	} while (0)
#else
#define get_task(v)                                                            \
	do {                                                                       \
		v->pid = current;                                                      \
	} while (0)
#endif

#ifndef __KERNEL__

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del((struct list_head *)entry->prev,
		   (struct list_head *)entry->next);
	entry->next = (void *) 0;
	entry->prev = (void *) 0;
}

static inline int list_empty(struct list_head *head)
{
	return head->next == head;
}

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((struct list_head *)(head)->next, typeof(*pos), member),	\
		n = list_entry((struct list_head *)pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry((struct list_head *)n->member.next, typeof(*n), member))
#endif

#define UNLOCK_COUNT_THERSHOLD 	1024

static inline uint32_t xor_random(int cid)
{
	static __thread uint32_t __rv;
	uint32_t v;

	if (__rv == 0)
		__rv = (uint32_t)cid;

	v = __rv;
	v ^= v << 6;
	v ^= (uint32_t)(v) >> 21;
	v ^= v << 7;
	__rv = v;

	return v & (UNLOCK_COUNT_THERSHOLD - 1);
}

/*
 * Declarations
 */
static inline int update_qnode_state_release(struct qnode *qnode,
					     uint64_t state);
static inline void update_qnode_state_park_to_unpark(struct qnode *qnode,
						     uint64_t count);
static inline void wake_up_all_waiters_in_snode(struct snode *snode);
static inline int release_any_active_waiter(struct snode *snode,
					    struct qnode *qnode, uint64_t count);
static inline int park_qnode(cstmcsvar_lock *lock, struct snode *snode,
			     struct qnode *qnode);

static inline uint16_t numa_get_gid(uint64_t ngid_vec, uint16_t nid);
static inline struct snode *get_snode(cstmcsvar_lock *lock, uint16_t nid);
static inline struct snode *find_snode(cstmcsvar_lock *lock, uint16_t nid);
static inline struct snode *add_snode(cstmcsvar_lock *lock, uint16_t nid,
				      uint16_t gid);
static inline struct snode *alloc_snode(cstmcsvar_lock *lock, int32_t nid);
static inline void *malloc_at_numa_node(size_t size, int32_t nid);

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

static void __always_inline numa_get_nid(struct nid_clock_info *v)
{
	const static uint32_t NUMA_ID_BASE = 1;
	uint32_t a, d, c;
	__asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));

	/* nid must be positive. */
	v->timestamp = (uint64_t)a | (((uint64_t)d) << 32);
	v->nid = ((c & 0xFFF) / CORES_PER_SOCKET) + NUMA_ID_BASE;
	v->cid = c & 0xFFF;

	dprintf("nid: %d, timestamp: %lu\n", v->nid, v->timestamp);
}

static uint64_t __always_inline rdtscp(void)
{
	uint32_t a, d;
	__asm __volatile("rdtscp; mov %%eax, %0; mov %%edx, %1; cpuid"
			 : "=r" (a), "=r" (d)
			 : : "%rax", "%rbx", "%rcx", "%rdx");
	return ((uint64_t) a) | (((uint64_t) d) << 32);
}

static inline void list_add_unsafe(struct list_head *new,
				   struct list_head *head)
{
	volatile struct list_head *old;

	/* there can be concurrent enqueuers */
	inc_atomic_count();
	new->next = head->next;

	old = smp_swap(&head->next, new);
	new->next = old;
	dprintf("updated new->next to old (%p)\n", old);
	smp_wmb();
}

static inline void list_del_unsafe(struct list_head *entry,
				   struct list_head *head)
{
	/* handling contention with the enqueuers */
	if (head->next == entry) {
		inc_atomic_count();
		if (smp_cas(&head->next, entry, entry->next)) {
			return;
		} else
			inc_casfail_count();
	}
}


int cstmcsvar_trylock(cstmcsvar_lock *L, cstmcsvar_qnode_ptr I)
{
	return 0;
}

static inline void acquire_global(cstmcsvar_lock *lock, struct snode *snode)
{
	struct snode *old_snode;

	snode->gnext = NULL;
	snode->status = STATE_PARKED;

	old_snode = (struct snode *)smp_swap(&lock->gtail, snode);
	if (!old_snode) {
		snode->status = STATE_LOCKED;
		return;
	}

	barrier();
	old_snode->gnext = snode; /* caching the next snode */

	while(snode->status == STATE_PARKED) {
		smp_rmb();
	}
	dprintf("got global lock for nid: %d\n", snode->nid);
}

static int __cstmcsvar_acquire_local_lock(cstmcsvar_lock *lock,
					  struct snode *snode,
					  struct qnode *qnode, int cid,
					  uint64_t timestamp)
{
	struct qnode cur_qnode;
	struct qnode *old_qnode, *next_qnode;
	int count = 0;
	int allow_local_acquire = 0;
	int ret;

	cur_qnode.cid = cid;
	cur_qnode.my_snode = snode;
     requeue:
	cur_qnode.status = UNPARKED_WAITER_STATE;
	cur_qnode.next = NULL;
	cur_qnode.in_list = false;

	old_qnode = smp_swap(&snode->qtail, &cur_qnode);
	if (old_qnode) {

		barrier();
		old_qnode->next = &cur_qnode;
		barrier();

		for (;;) {
			if (LOCKING_STATE(cur_qnode.status) != WAIT)
				break;
			if (++count == 1000 &&
			    (rdtscp() - timestamp) > 1000) {
				count = 0;
				ret = park_qnode(lock, snode, &cur_qnode);
				if (ret == QNODE_UNPARKED)
					timestamp = rdtscp();
				else {
					if (LOCKING_STATE(cur_qnode.status) ==
					    ACQUIRE_PARENT) {
						dprintf("status: %lu\n",
						       LOCKING_STATE(cur_qnode.status));
						break;
					} else if (LOCKING_STATE(cur_qnode.status) ==
						   REQUEUE)
						goto requeue;
				}
			}
			smp_rmb();
		}

		if (LOCKING_STATE(cur_qnode.status) < ACQUIRE_PARENT)
			allow_local_acquire = 1;
	}

	next_qnode = cur_qnode.next;
	snode->qnext = next_qnode; /* caching the next qnode */
	if (!next_qnode) {
		barrier();
		if (!smp_cas(&snode->qtail, &cur_qnode, &snode->qnext)) {
			while(!cur_qnode.next)
				smp_rmb();
			snode->qnext = cur_qnode.next;
		}
	}

	if (!allow_local_acquire) {
		barrier();
		acquire_global(lock, snode);
		lock->serving_socket = snode;
	}
	return 0;
}

void cstmcsvar_acquire(cstmcsvar_lock *lock, cstmcsvar_qnode_ptr me)
{
	struct nid_clock_info info;
	struct snode *snode;
	int32_t nid;

	/* get both timestamp and node id */
	numa_get_nid(&info);
	dprintf("called for acquire\n");
	nid = info.nid;

	snode = get_snode(lock, nid);

	__cstmcsvar_acquire_local_lock(lock, snode, me, info.cid,
				       info.timestamp);
}

static inline void __cstmutex_global_unlock(cstmcsvar_lock *lock,
					    struct snode *snode)
{
	if (!snode->gnext) {
		if (smp_cas(&lock->gtail, snode, NULL)) {
			return;
		}

		while(!snode->gnext)
			smp_rmb();
	}
	snode->gnext->status = STATE_LOCKED;
	smp_wmb();
}

static inline void __cstmutex_local_unlock(cstmcsvar_lock *lock,
					   struct snode *snode)
{
	struct qnode *next_qnode = snode->qnext;

	barrier();
	if (!next_qnode) {
		if (smp_cas(&snode->qtail, &snode->qnext, NULL)) {
			wake_up_all_waiters_in_snode(snode);
			return;
		}

		while(!snode->qnext)
			smp_rmb();
		next_qnode = snode->qnext;
	}
	if(!update_qnode_state_release(next_qnode, ACQUIRE_PARENT)) {
#ifndef PARKING
		update_qnode_state_park_to_unpark(next_qnode, ACQUIRE_PARENT);
#else
		if (!release_any_active_waiter(snode,
					       next_qnode, ACQUIRE_PARENT)) {
			dprintf("waking up waiter: %d\n", next_qnode->cid);
			spin_lock(&snode->wait_lock);
			next_qnode->in_list = false;
			list_del(&next_qnode->wait_node);
			update_qnode_state_park_to_unpark(next_qnode, ACQUIRE_PARENT);
			spin_unlock(&snode->wait_lock);
		}
#endif
	}
	smp_wmb();
}

void cstmcsvar_release(cstmcsvar_lock *lock, cstmcsvar_qnode_ptr me)
{
	struct qnode *next_qnode;
	struct snode *snode;
	uint64_t cur_count;

	snode = (struct snode *)lock->serving_socket;

	cur_count = ++snode->num_proc;
	if(cur_count == NUMA_BATCH_SIZE) {
		__cstmutex_global_unlock(lock, snode);
		if (!list_empty(&snode->wait_list))
			wake_up_all_waiters_in_snode(snode);
		__cstmutex_local_unlock(lock, snode);
		snode->num_proc = 0;
		return;
	}

	next_qnode = snode->qnext;
	if (next_qnode) {
		if(!update_qnode_state_release(next_qnode, cur_count)) {
#ifndef PARKING
			update_qnode_state_park_to_unpark(next_qnode, cur_count);
#else
			if(!release_any_active_waiter(snode,
						      next_qnode, cur_count)) {
				dprintf("could not find any next_qnode\n");
				goto out;
			}
#endif
		}
		dprintf("next_qnode got the lock: %d\n", next_qnode->cid);
		return;
	}

     out:
	__cstmutex_global_unlock(lock, snode);
	__cstmutex_local_unlock(lock, snode);
}

int is_free_cstmcsvar(cstmcsvar_lock *L ){
	if ((L) == NULL) return 1;
	return 0;
}

/*
   Methods for easy lock array manipulation
   */

cstmcsvar_global_params* init_cstmcsvar_array_global(uint32_t num_locks) {
	uint32_t i;
	cstmcsvar_global_params* the_locks =
		(cstmcsvar_global_params*)malloc(num_locks * sizeof(cstmcsvar_global_params));
	for (i=0;i<num_locks;i++) {
		the_locks[i].the_lock=(cstmcsvar_lock*)malloc(sizeof(cstmcsvar_lock));
		memset(the_locks[i].the_lock, 0, sizeof(cstmcsvar_lock));
		INIT_LIST_HEAD(&the_locks[i].the_lock->numa_list.head);
	}
	MEM_BARRIER;
	return the_locks;
}


cstmcsvar_qnode** init_cstmcsvar_array_local(uint32_t thread_num, uint32_t num_locks) {
	set_cpu(thread_num);

	//init its qnodes
	uint32_t i;
	cstmcsvar_qnode** the_qnodes = (cstmcsvar_qnode**)malloc(num_locks * sizeof(cstmcsvar_qnode*));
	for (i=0;i<num_locks;i++) {
		the_qnodes[i]=(cstmcsvar_qnode*)malloc(sizeof(cstmcsvar_qnode));
	}
	MEM_BARRIER;
	return the_qnodes;

}

void end_cstmcsvar_array_local(cstmcsvar_qnode** the_qnodes, uint32_t size) {
	uint32_t i;
	for (i = 0; i < size; i++) {
		free(the_qnodes[i]);
	}
	free(the_qnodes);
}

void end_cstmcsvar_array_global(cstmcsvar_global_params* the_locks, uint32_t size) {
	uint32_t i;
	for (i = 0; i < size; i++) {
		free(the_locks[i].the_lock);
	}
	free(the_locks); 
}

int init_cstmcsvar_global(cstmcsvar_global_params* the_lock) {
	the_lock->the_lock=(cstmcsvar_lock*)malloc(sizeof(cstmcsvar_lock));
	memset(the_lock->the_lock, 0, sizeof(cstmcsvar_lock));
	INIT_LIST_HEAD(&the_lock->the_lock->numa_list.head);
	MEM_BARRIER;
	return 0;
}


int init_cstmcsvar_local(uint32_t thread_num, cstmcsvar_qnode** the_qnode) {
	set_cpu(thread_num);

	(*the_qnode)=(cstmcsvar_qnode*)malloc(sizeof(cstmcsvar_qnode));

	MEM_BARRIER;
	return 0;

}

void end_cstmcsvar_local(cstmcsvar_qnode* the_qnodes) {
	free(the_qnodes);
}

void end_cstmcsvar_global(cstmcsvar_global_params the_locks) {
	free(the_locks.the_lock);
}

static inline struct snode *get_snode(cstmcsvar_lock *lock, uint16_t nid)
{

	struct snode *snode, *tmp_snode;
	uint16_t gid;

     retry_snode:
	/* short cut for serving_socket */
	dprintf("checking whether serving socket has same nid or not\n");
	tmp_snode = (struct snode *)lock->serving_socket;
	if (tmp_snode && tmp_snode->nid == nid) {
		dprintf("found the snode with nid: %d\n", nid);
		return tmp_snode;
	}

	/* get snode */
	gid = numa_get_gid(lock->ngid_vec, nid);
	dprintf("current gid: %d\n", gid);
	/* This is where the read CS begins */
	/* check whether the list is in use or not */
	if (numa_gid_not_empty(gid)) {
		/* snode may be already existing, let's get it */
		dprintf("GID is still there, trying to find the snode\n");
		snode = find_snode(lock, nid);
	} else {
		/* although number exists, but it is not present, adding it */
		dprintf("couldn't find the snode, going to allocate\n");
		snode = add_snode(lock, nid, gid);
	}
	/*
	 * even though gid was existing, but snode has not been created,
	 * someone else is doing it for us
	 */
	if (!snode) {
		smp_rmb();
		goto retry_snode;
	}
	return snode;
}

static inline uint16_t numa_get_gid(uint64_t ngid_vec, uint16_t nid)
{
	uint64_t nid_mask = NUMA_NID_MASK(nid);
	uint16_t gid_value = (ngid_vec & nid_mask) >> NUMA_GID_SHIFT(nid);
	return gid_value;
}

static inline uint64_t  numa_set_gid(uint64_t ngid_vec,
				     uint16_t nid, uint16_t gid)
{
	uint64_t nid_mask = NUMA_NID_MASK(nid);
	uint64_t gid_mask = NUMA_GID_MASK(nid, gid);
	return (ngid_vec & ~nid_mask) | gid_mask;
}

/**
 * init of snode
 */
static inline struct snode *find_snode(cstmcsvar_lock *lock, uint16_t nid)
{
	struct snode *snode;
	struct list_head *numa_entry;

	/* check whether it belongs to the serving snode */
	snode = (struct snode *)lock->serving_socket;
	if (snode && snode->nid == nid) {
		dprintf("found the current serving socket\n");
		return snode;
	}

	dprintf("going to find the snode with nid: %d\n", nid);
	numa_entry = (struct list_head *)lock->numa_list.head.next;
	while (numa_entry) {
		snode = list_entry(numa_entry, struct snode, numa_node);
		dprintf("iterating over snode with nid: %d\n", snode->nid);

		if (snode->nid == nid) {
			dprintf("found the snode\n");
			return snode;
		}
		numa_entry = (struct list_head *)numa_entry->next;
	}
	dprintf("couldn't find the snode with nid: %d\n", nid);
	return NULL;
}

static inline struct snode *add_snode(cstmcsvar_lock *lock, uint16_t nid,
				      uint16_t gid)
{
	uint64_t old_ngid_vec;
	uint64_t new_ngid_vec;
	uint16_t new_gid;
	struct snode *snode = NULL;

	/*
	 * XXX: I can simplify this one to have 64 bit vector to get the snode.
	 * BUT, I will keep it if we go for the cst global memory allocator
	 * for the kernel. If we don't then can be easily changed.
	 */

	new_gid = numa_gid_inc(gid) | 0x1;
	do {
		/* prepare new_ngid_vec */
		old_ngid_vec = lock->ngid_vec;
		dprintf("old ngid vec: %lu\n", old_ngid_vec);

		new_ngid_vec = numa_set_gid(old_ngid_vec, nid, new_gid);
		dprintf("new ngid vec: %lu\n", new_ngid_vec);

		/*
		 * do another check again since, it is possible that somehow
		 * someone might have obtained the same gid
		 */
		if (old_ngid_vec == new_ngid_vec) {
			dprintf("someone is in progress, falling back\n");
			return find_snode(lock, nid);
		}

		/* try to atomically update ngid_vec using cas */
		inc_atomic_count();
		if (lock->ngid_vec == old_ngid_vec &&
		    smp_cas(&lock->ngid_vec, old_ngid_vec, new_ngid_vec)) {
			/* succeeded in updating ngid_vec
			 * meaning that this thread is a winner
			 * even if there was contention on updating ngid_vec */
			dprintf("the ngid vector successfully updated from %lu to %lu\n",
				old_ngid_vec, new_ngid_vec);
			break;
		} else  {
			inc_casfail_count();
			/*
			 * this thread is a looser in updating ngid_vec
			 * there are two cases:
			 */

			/**
			 * 1) if snode for nid is added by other thread,
			 *    go back to the beginning of the lock code
			 */
			if (numa_gid_not_empty(numa_get_gid(lock->ngid_vec, nid))) {
				dprintf("someone already added for nid: %d\n", nid);
				return find_snode(lock, nid);
			}

			/**
			 * 2) otherwise snode for other nid is added,
			 *    retry to add_snode() for this nid
			 */
			dprintf("failed miserably as someone else added, trying again\n");
		}
		dprintf("going to loop again\n");
	} while (1);

	/*
	 * This thread succeeded in updating gid for nid.
	 * The gid for this nid is marked as not-empty.
	 * This thread has the responsibility of actually allocating
	 * snode and inserting it into the numa_list. Until it is done,
	 * all other threads for the same nid will be spinning
	 * in the retry loop of mutex_lock().
	 */
	dprintf("allocating the snode with nid: %d\n", nid);
	snode = alloc_snode(lock, (int32_t)nid);
	snode->nid = 0;
	smp_wmb();

	/* add the new snode to the list */
	dprintf("adding snode with nid %d to the numa list\n", nid);
	list_add_unsafe(&snode->numa_node, &lock->numa_list.head);
	snode->nid = nid;
	smp_wmb();
	return snode;
}

static inline struct snode *alloc_snode(cstmcsvar_lock *lock, int32_t nid)
{
	struct snode *snode;
	dprintf("malloc snode with nid: %d\n", nid);
	snode = malloc_at_numa_node(sizeof(*snode), nid);
	snode->qtail = NULL;
	snode->qnext = NULL;
	snode->num_proc = 0;

	snode->status = STATE_PARKED;
	snode->gnext = NULL;
	snode->numa_node.next = NULL;
	INIT_LIST_HEAD(&snode->wait_list);
	spinlock_init(&snode->wait_lock);
	snode->my_lock = lock;
	return snode;
}

/**
 * allocation / deallocation of snode
 */
static inline void *malloc_at_numa_node(size_t size, int32_t nid)
{
	return malloc(size);
}

/* state stuff */

static inline int update_qnode_state_release(struct qnode *qnode,
					     uint64_t state)
{
	uint64_t new_status = (PARKING_STATE_MASK(UNPARKED)) | state;

	return ((qnode->status == UNPARKED_WAITER_STATE) &&
		smp_cas(&qnode->status, UNPARKED_WAITER_STATE, new_status));
}

static inline int update_qnode_state_park(struct qnode *qnode)
{
	return ((qnode->status == UNPARKED_WAITER_STATE) &&
		 smp_cas(&qnode->status, UNPARKED_WAITER_STATE,
			 PARKED_WAITER_STATE));
}

static inline void wait_for_unparking(struct qnode *qnode)
{
	dprintf("qnode parking state: %d\n", PARKING_STATE(qnode->status));
	for (;;) { /* test for userspace */
		if (PARKING_STATE(qnode->status) == UNPARKED)
			break;
	}
}

static inline void update_qnode_state_park_to_unpark(struct qnode *qnode,
					       uint64_t count)
{
	dprintf("%s: update qnode (%d) state to unparked\n", __func__,
	       qnode->cid);
	if (!smp_cas(&qnode->status, PARKED_WAITER_STATE,
		     ((PARKING_STATE_MASK(UNPARKED)) | count))) {
		dprintf("qnode: %d, status: %lu\n", qnode->cid,
		       qnode->status);
		dprintf("count: %lu\n", count);
		assert(0);
	}
}

static inline void wake_up_all_waiters_in_snode(struct snode *snode)
{
	spin_lock(&snode->wait_lock);
	if (!list_empty(&snode->wait_list)) {
		dprintf("%s: wakingup everyone\n", __func__);
		struct qnode *pos, *tmp;
		list_for_each_entry_safe(pos, tmp,
					 &snode->wait_list, wait_node) {
			dprintf("%s: waking up parked waiter: %d\n", __func__,
				pos->cid);
			if (pos->in_list) {
				pos->in_list = false;
				list_del(&pos->wait_node);
			}
			update_qnode_state_park_to_unpark(pos, REQUEUE);
		}
		/* ??? wake up all / do we really need to wake up all ??? */
		dprintf("%s: wakingup everyone .... done\n", __func__);
	}
	spin_unlock(&snode->wait_lock);
}

static inline int release_any_active_waiter(struct snode *snode,
					    struct qnode *qnode, uint64_t count)
{
	struct qnode *tmp;

	tmp = qnode;
#if 0
	spin_lock(&snode->wait_lock);
	dprintf("=== start ===\n");
	for (;;) {
		if (update_qnode_state_release(tmp, count)) {
			dprintf("%d got the lock\n", tmp->cid);
			dprintf("=== end ===\n");
			spin_unlock(&snode->wait_lock);
			return true;
		}
		dprintf("couldn't get the lock: %d\n", tmp->cid);
		if (!tmp->in_list) {
			assert(0);
			dprintf("adding qnode: %d\n", tmp->cid);
			list_add_tail(&tmp->wait_node, &snode->wait_list);
			tmp->in_list = true;
		}
		smp_rmb();
		if (!tmp->next) {
			if (snode->qtail != tmp) {
				while (!tmp->next)
					smp_rmb();
			} else {
				break;
			}
		} else
			tmp = (struct qnode *)tmp->next;
	}
	dprintf("=== end ===\n");
	spin_unlock(&snode->wait_lock);
#endif
	for (;;) {
		if (update_qnode_state_release(tmp, count)) {
			return true;
		}
		if (!tmp->next) {
			if (snode->qtail != tmp) {
				while (!tmp->next)
					smp_rmb();
			} else
				break;
		} else
			tmp = (struct qnode *)tmp->next;
	}
	return false;
}

static inline int park_qnode(cstmcsvar_lock *lock, struct snode *snode,
			     struct qnode *qnode)
{
	if (!spin_trylock(&snode->wait_lock)) {
		if (!update_qnode_state_park(qnode)) {
			dprintf("failed to change to park state\n");
			goto unlock_out;
		}
		dprintf("parked qnode: %d\n", qnode->cid);
		assert(qnode->in_list == 0);
		list_add_tail(&qnode->wait_node, &snode->wait_list);
		qnode->in_list = true;
		spin_unlock(&snode->wait_lock);
		wait_for_unparking(qnode);
		dprintf("scheduled in qnode: %d\n", qnode->cid);
#ifdef PARKING
		return QNODE_REQUEUE;
#endif
	}
     out:
	return QNODE_UNPARKED;
     unlock_out:
	spin_unlock(&snode->wait_lock);
	return QNODE_UNPARKED;
}
