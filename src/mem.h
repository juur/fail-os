#ifndef _MEM_H
#define _MEM_H

#include "klibc.h"
#include "proc.h"

#define KERN_POOLS  6

struct _kp_head;
struct _kp_node;

#define DESC_LEN	16

#define KP_MAGIC	0x6675636b63756e74ULL

typedef struct _kp_node {
	struct _kp_node		*next;
	struct _kp_node		*prev;
	struct _kp_head		*head;
	struct task			*owner;

	uint64_t	magic;
	uint64_t	len;
	uint64_t	flags;
	//uint64_t	spare;

	char		desc[DESC_LEN];
}  __attribute__((packed)) kp_node;


#define NODE_SIZE		(sizeof(kp_node))
#define NODE_DATA(x)	(((uint64_t)(x))+sizeof(kp_node))

#define	KP_FREE 	(1<<0)
#define	KP_ALIGN 	(1<<1)

typedef struct _kp_head {
	struct _kp_head *loc;
	kp_node	        *first;

	uint64_t	magic;
	uint64_t	len;
	uint64_t	pool;
	uint64_t	end;
} __attribute__((packed)) kp_head;

#define HEAD_SIZE	(sizeof(kp_head))

struct ring_head {
	uint8_t *buffer;
	int length;
	int read;
	int write;
	int data;
};


extern int kplock[KERN_POOLS];
extern uint8_t *kern_pool[KERN_POOLS];
extern bool memdebug;

/* kmalloc flags */
#define KMF_ZERO	0x1

bool is_valid(const void *vaddr)__attribute__((nonnull));
void kscan(void);
void *kmalloc(unsigned long len, const char *desc, void *owner, int flags)__attribute__((malloc));
void *kmalloc_align(unsigned long len, const char *desc, void *owner, int flags)__attribute__((malloc));
//void lock_pool(unsigned long pool);
//void unlock_pool(unsigned long pool);
//void dump_pool(const kp_head *kph);
void dump_pools(void);
void init_pool(void *, unsigned long len, uint64_t pool)__attribute__((nonnull));
const char *find_sym(const void *addr);
bool ring_write(struct ring_head *rh, uint8_t byte)__attribute__((nonnull));
bool ring_read(struct ring_head *rh, uint8_t *byte)__attribute__((nonnull));
void print_ring(const struct ring_head *rh)__attribute__((nonnull));
struct ring_head *ring_init(int length, void *owner);
void copy_to_user(uint8_t *dst, const struct task *task, const uint8_t *data, size_t len);
int kfree(void *free)__attribute__((nonnull));
int do_one_pool(struct task *owner);
void describe_mem(uint8_t *addr);
void *do_brk(struct task *const t, const void *const brk);

#endif

// vim: set ft=c:
