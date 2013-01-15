#ifndef _MEM_H
#define _MEM_H

#include "proc.h"

#define KERN_POOLS  6

struct _kp_head;
struct _kp_node;

#define DESC_LEN	15

typedef struct _kp_node {
//	uint64	tmp0[4];
	struct _kp_node *next;
	struct _kp_head *head;
	struct _kp_node *prev;
	struct task *owner;
	uint64	len;
	uint8	flags;
	char	desc[DESC_LEN];
//	uint64	tmp1[4];
}  
#ifdef __GNUC__
__attribute__((packed))
#endif
kp_node;


#define NODE_SIZE		(sizeof(kp_node))
#define NODE_DATA(x)	(((uint64)(x))+sizeof(kp_node))

#define	KP_FREE 	(1<<0)
#define	KP_ALIGN 	(1<<1)

typedef struct _kp_head {
	struct _kp_head *loc;
	uint64	len;
	uint64	pool;
	kp_node *first;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
kp_head;
#define HEAD_SIZE	(sizeof(kp_head))


struct ring_head {
	unsigned char *buffer;
	int length;
	int read;
	int write;
	int data;
};


extern int kplock[KERN_POOLS];
extern char *kern_pool[KERN_POOLS];
extern bool memdebug;

#include "symtable.h"

bool is_valid(void *vaddr);
void kscan();
void *kmalloc(unsigned long len, char *desc, void *owner);
void *kmalloc_align(unsigned long len, char *desc, void *owner);
void lock_pool(unsigned long pool);
void unlock_pool(unsigned long pool);
void dump_pool(kp_head *kph);
void dump_pools();
void init_pool(void *, unsigned long len, uint64 pool);
const char *find_sym(void *addr);
bool ring_write(struct ring_head *rh, unsigned char byte);
bool ring_read(struct ring_head *rh, unsigned char *byte);
void print_ring(struct ring_head *rh);
struct ring_head *ring_init(int length, void *owner);
void copy_to_user(uint8 *dst, struct task *task, uint8 *data, uint64 len);
int kfree(void *free);
int do_one_pool(struct task *owner);
void describe_mem(uint64 addr);

#endif

