/*
 * File: cstmcs.c
 * Author: Sanidhya Kashyap <sanidhya@gatech.edu>
 *         Changwoo Min <changwoo@gatech.edu>
 *
 * Description:
 *      CSTMCS lock implementation
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




#include "cstmcs.h"

/**
 * common
 */
#define INIT_LIST_HEAD(ptr)                                                    \
    do {                                                                       \
        (ptr)->next = (ptr);                                                   \
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

#define FIRST_ELEM      1
#define ACQUIRE_PARENT  (UINT64_MAX - 1)
#define WAIT            UINT64_MAX

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

static uint64_t atomic_count = 0;
static uint64_t release_count = 0;
static uint64_t cas_failures = 0;

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
#endif

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
#endif

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

/*
 * Declarations
 */
static inline uint16_t numa_get_gid(uint64_t ngid_vec, uint16_t nid);
static inline struct snode *get_snode(cstmcs_lock *lock, uint16_t nid);
static inline struct snode *find_snode(cstmcs_lock *lock, uint16_t nid);
static inline struct snode *add_snode(cstmcs_lock *lock, uint16_t nid,
                                      uint16_t gid);
static inline struct snode *alloc_snode(cstmcs_lock *lock, int32_t nid);
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
    v->nid = ((c & 0xFFF) / CORES_PER_SOCKET) + NUMA_ID_BASE;
    v->timestamp = (uint64_t)a | (((uint64_t)d) << 32);

    update_cid(v, ((c+1) & 0xFFF));
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

    /*
     * Node addition approach:
     * The new node is always inserted at the head node
     *                          -------------
     *                          |           |
     *                          |  Node B   |
     *              ----------->|           |-----------
     *             /            -------------            \
     *            /                                       \
     *           /                                         \
     *          /                                           >
     *  -------------               \ /                     -------------
     *  |           |================\====================>>|           |
     *  |   HEAD    |               / \                     |  Node A   |
     *  |           |                                       |           |
     *  -------------                                       -------------
     *
     * The only caveat with this approach is that this doubly linked list is
     * derived from the lock free linked list approach. But, we are try to
     * follow a strict protocol for moving forward with the next pointer,
     * therefore it should not be an issue.
     */

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


int cstmcs_trylock(cstmcs_lock *L, cstmcs_qnode_ptr I)
{
    return 0;
}

static inline void acquire_global(cstmcs_lock *lock, struct snode *snode)
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
    old_snode->gnext = snode;

    while(snode->status == STATE_PARKED) {
        smp_rmb();
    }

    dprintf("got global lock for nid: %d\n", snode->nid);
}

static int __cstmcs_acquire_local_lock(cstmcs_lock *lock,
                                       struct snode *snode, struct qnode *qnode)
{
    struct qnode *old_qnode;

    qnode->next = NULL;
    qnode->status = WAIT;

    old_qnode = smp_swap(&snode->qtail, qnode);
    if (old_qnode) {
        old_qnode->next = qnode;
        uint64_t cur_status;

        barrier();
        while((cur_status = qnode->status) == WAIT)
            smp_rmb();

        if (cur_status < ACQUIRE_PARENT)
            goto out;
    }

    qnode->status = FIRST_ELEM;
    acquire_global(lock, snode);
    lock->serving_socket = snode;

 out:
    return 0;
}


void cstmcs_acquire(cstmcs_lock *lock, cstmcs_qnode_ptr me)
{
    struct snode *snode;
    int32_t nid;
    struct nid_clock_info info;

    /* get both timestamp and node id */
    numa_get_nid(&info);
    dprintf("called for acquire\n");
    nid = info.nid;

    snode = get_snode(lock, nid);

    __cstmcs_acquire_local_lock(lock, snode, me);
}

static inline void __cstmutex_global_unlock(cstmcs_lock *lock,
                                            struct snode *snode)
{
    if (!snode->gnext) {
        if (smp_cas(&lock->gtail, snode, NULL))
            return;

        while(!snode->gnext)
            smp_rmb();
    }
    snode->gnext->status = STATE_LOCKED;
    smp_wmb();
}

static inline void __cstmutex_local_unlock(struct snode *snode,
                                           struct qnode *qnode)
{
    if (!qnode->next) {
        if (smp_cas(&snode->qtail, qnode, NULL))
            return;

        while(!qnode->next)
            smp_rmb();
    }

    qnode->next->status = ACQUIRE_PARENT;
    smp_wmb();
}

void cstmcs_release(cstmcs_lock *lock, cstmcs_qnode_ptr me)
{
    struct qnode *next_qnode;
    struct snode *snode;
    uint64_t cur_count;

    snode = (struct snode *)lock->serving_socket;

    cur_count = me->status;
    if(cur_count == NUMA_BATCH_SIZE) {
	    if (!snode->gnext) {
		    cur_count = 0;
		    goto pass_locally;
	    }
        __cstmutex_global_unlock(lock, snode);
        __cstmutex_local_unlock(snode, me);
	return;
    }

 pass_locally:
    next_qnode = (struct qnode *)me->next;
    if (next_qnode) {
        next_qnode->status = cur_count + 1;
        return;
    }

    __cstmutex_global_unlock(lock, snode);
    __cstmutex_local_unlock(snode, me);
}

int is_free_cstmcs(cstmcs_lock *L ){
    if ((L) == NULL) return 1;
    return 0;
}

/*
   Methods for easy lock array manipulation
   */

cstmcs_global_params* init_cstmcs_array_global(uint32_t num_locks) {
    uint32_t i;
    cstmcs_global_params* the_locks =
        (cstmcs_global_params*)malloc(num_locks * sizeof(cstmcs_global_params));
    for (i=0;i<num_locks;i++) {
        the_locks[i].the_lock=(cstmcs_lock*)malloc(sizeof(cstmcs_lock));
        memset(the_locks[i].the_lock, 0, sizeof(cstmcs_lock));
        INIT_LIST_HEAD(&the_locks[i].the_lock->numa_list.head);
    }
    MEM_BARRIER;
    return the_locks;
}


cstmcs_qnode** init_cstmcs_array_local(uint32_t thread_num, uint32_t num_locks) {
    set_cpu(thread_num);

    //init its qnodes
    uint32_t i;
    cstmcs_qnode** the_qnodes = (cstmcs_qnode**)malloc(num_locks * sizeof(cstmcs_qnode*));
    for (i=0;i<num_locks;i++) {
        the_qnodes[i]=(cstmcs_qnode*)malloc(sizeof(cstmcs_qnode));
    }
    MEM_BARRIER;
    return the_qnodes;

}

void end_cstmcs_array_local(cstmcs_qnode** the_qnodes, uint32_t size) {
    uint32_t i;
    for (i = 0; i < size; i++) {
        free(the_qnodes[i]);
    }
    free(the_qnodes);
}

void end_cstmcs_array_global(cstmcs_global_params* the_locks, uint32_t size) {
    uint32_t i;
    for (i = 0; i < size; i++) {
        free(the_locks[i].the_lock);
    }
    free(the_locks); 
}

int init_cstmcs_global(cstmcs_global_params* the_lock) {
    the_lock->the_lock=(cstmcs_lock*)malloc(sizeof(cstmcs_lock));
    memset(the_lock->the_lock, 0, sizeof(cstmcs_lock));
    INIT_LIST_HEAD(&the_lock->the_lock->numa_list.head);
    MEM_BARRIER;
    return 0;
}


int init_cstmcs_local(uint32_t thread_num, cstmcs_qnode** the_qnode) {
    set_cpu(thread_num);

    (*the_qnode)=(cstmcs_qnode*)malloc(sizeof(cstmcs_qnode));

    MEM_BARRIER;
    return 0;

}

void end_cstmcs_local(cstmcs_qnode* the_qnodes) {
    free(the_qnodes);
}

void end_cstmcs_global(cstmcs_global_params the_locks) {
    free(the_locks.the_lock);
}

static inline struct snode *get_snode(cstmcs_lock *lock, uint16_t nid)
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
static inline struct snode *find_snode(cstmcs_lock *lock, uint16_t nid)
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

static inline struct snode *add_snode(cstmcs_lock *lock, uint16_t nid,
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

static inline struct snode *alloc_snode(cstmcs_lock *lock, int32_t nid)
{
    struct snode *snode;
    dprintf("malloc snode with nid: %d\n", nid);
    snode = malloc_at_numa_node(sizeof(*snode), nid);
    snode->gnext = NULL;
    snode->numa_node.next = NULL;
    snode->status = STATE_PARKED;
    snode->qtail = NULL;
    return snode;
}

/**
 * allocation / deallocation of snode
 */
static inline void *malloc_at_numa_node(size_t size, int32_t nid)
{
    return malloc(size);
}
