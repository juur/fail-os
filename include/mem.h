#ifndef _MEM_H
#define _MEM_H

#include <ktypes.h>
#include <page.h>

#define KERN_POOLS  6

struct _kp_head;
struct _kp_node;

#define DESC_LEN	72

#define KP_MAGIC	0x6675636b63756e74ULL
#define PAD_SIZE	8

typedef struct _kp_node {
	char		pad0[PAD_SIZE];

	struct _kp_node		*next;
	struct _kp_node		*prev;
	struct _kp_head		*head;
	struct task			*owner;

	uint64_t	magic;
	uint64_t	len;
	uint64_t	flags;
	//uint64_t	spare;

	char		desc[DESC_LEN];

	char		pad1[PAD_SIZE];

	char		data[] __attribute__ ((nonstring));
}  __attribute__((packed)) kp_node;


#define NODE_SIZE		(sizeof(kp_node))
#define NODE_DATA(x)    ((void *)&((x)->data))

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
	uint8_t *buffer __attribute__ ((nonstring));
	int length;
	int read;
	int write;
	int data;
};


extern int kplock[KERN_POOLS];
extern void *kern_pool[KERN_POOLS];
extern uintptr_t high_mem_start, top_of_mem, kern_mem_end, kern_heap_top;
extern uintptr_t kernel_ds_end;
extern uint64_t num_kern_pools, pool_page_num;
extern uint64_t pagebm_max, total_frames;

extern bool mem_init;
extern bool nosched;
extern bool memdebug;
extern bool boot_done;


/* kmalloc flags */
#define KMF_ZERO	0x1

extern bool  is_valid(const void *vaddr)__attribute__((nonnull));
extern void  kscan(void);
extern void  init_pool(void *, unsigned long len, uint64_t pool)__attribute__((nonnull));
extern void  _kfree(void *free, const char *, const char *, int)__attribute__((tainted_args));
extern void *_kmalloc(unsigned long len, const char *desc, void *owner, int flags, const char *, const char *, int) __attribute__ (( malloc(_kfree,1), warn_unused_result, alloc_size(1), access(read_only, 2) ));
extern void *kmalloc_align(unsigned long len, const char *desc, void *owner, int flags) __attribute__ (( malloc(_kfree,1), warn_unused_result, alloc_size(1), assume_aligned(PAGE_SIZE), access(read_only, 2)));
extern void  memcpy_to_user(const pt_t *pt, char *dst, const char *src, size_t len);
extern int   do_one_pool(void);
extern void  kfree_all(const struct task *t) __attribute__((nonnull));

extern bool              ring_write(struct ring_head *rh, uint8_t byte) __attribute__((nonnull));
extern bool              ring_read(struct ring_head *rh, uint8_t *byte) __attribute__((nonnull, access(write_only, 2)));
extern struct ring_head *ring_init(int length, void *owner) __attribute__((warn_unused_result));

extern void *do_brk(struct task *t, const void *brk)__attribute__((nonnull(1), warn_unused_result));

extern const char *find_sym(const void *addr);
extern void  print_ring(const struct ring_head *rh)__attribute__((nonnull));
extern void  dump_mem(const void *, size_t cnt);
extern void  dump_pools(void);
extern void  describe_mem(uint8_t *addr);
extern void  print_kmem_stats(void);

#define kfree(x) _kfree((x), __FILE__, __func__, __LINE__)
#define kmalloc(l,d,o,f) _kmalloc((l),(d),(o),(f),__FILE__,__func__,__LINE__)

#endif
// vim: set ft=c:
