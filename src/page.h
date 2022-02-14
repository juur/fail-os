#ifndef _PAGE_H
#define _PAGE_H

#include "klibc.h"

#define KERN_MEM (64ULL*0x1000000ULL)

#define TABLE_ENTRIES	512

typedef struct {
	unsigned	offset:12;
	unsigned	pml1_offset:9;
	unsigned	pml2_offset:9;
	unsigned	pml3_offset:9;
	unsigned	pml4_offset:9;
	unsigned	sign_extend:16;
} __attribute__((packed)) kb_pe;

typedef struct {
	unsigned	offset:21;
	unsigned	pml2_offset:9;
	unsigned	pml3_offset:9;
	unsigned	pml4_offset:9;
	unsigned	sign_extend:16;
} __attribute__((packed)) mb_pe;

typedef struct {
	unsigned	offset:30;
	unsigned	pml3_offset:9;
	unsigned	pml4_offset:9;
	unsigned	sign_extend:16;
} __attribute__((packed)) gb_pe;

typedef union {
	kb_pe k;
	mb_pe m;
	gb_pe g;
	uint64_t addr;
} __attribute__((packed)) v_addr;

#define PEF_P		0x001
#define	PEF_W		0x002
#define	PEF_U		0x004
#define PEF_PWT		0x008
#define	PEF_PCD		0x010
#define PEF_A		0x020
#define PEF_D		0x040
#define	PEF_PAT		0x080
#define PEF_LAST	0x080
#define	PEF_G		0x100
#define PEF_COW		0x200
#define	PEF_AVL1	0x400
#define	PEF_AVL2	0x800

#define	PEF_NX		(1<<64)

typedef struct {
	unsigned	present:1;		// 0
	unsigned	write:1;		// 1
	unsigned	user:1;			// 2
	unsigned	pwt:1;			// 3
	unsigned	pcd:1;			// 4
	unsigned	access:1;		// 5
	unsigned	dirty:1;		// 6
	unsigned	last:1;			// 7 for a PML3/PML2 a 1 means no more PMLs
								// otherwise is pat

	unsigned	global:1;		// 8
	unsigned	cow:1;			// 9: 1 bit of AVL
	unsigned	avl:2;			// 10,11: 2 free bits i AVL

	uint64_t	base:40;		// 12,..,50; for lowest PML 12=pat

	unsigned	avail:11;		// 51,..,62

	unsigned	nx:1;			// 63
} __attribute__((packed)) pe_t;

#define PT_SIZE	512

typedef union { 
	pe_t table_pe[PT_SIZE]; 
	uint64_t table_u64[PT_SIZE];
}  
#ifdef __GNUC__
__attribute__((packed))
#endif
pt_t;

#define GET_PTP(x)      (pt_t *)((uint64_t)(x)->base << 12)
#define SET_PTP(x,y)    ((x)->base = ((y) >> 12))

#define GET_PE(x,y,z)   ((x)->table_pe[(y).k.z])
#define GET_PE_N(x,y)   ((x)->table_pe[(y)])

#define GET_PHYS(x,y,z) (((x)->base << 12) + (z).y.offset)
#define GET_PHYS_K(x,y) (((x)->base << 12) + (y).k.offset)
/* FIXME: */
#define SET_PHYS(x,y)   ((x)->base = ((y) >> 12) & 0xffffffff)
#define SET_PHYS_K(x,y) ((x)->base = ((y) >> 12) & 0xffffffff)

#define GET_VIRT(a,b,c,d)   (d<<12|c<<21|b<<30|a<<39)

struct task;

bool create_page_entry_1g(pt_t *pt4, uint64_t _virt, uint64_t _phys, int flag, struct task *owner)__attribute__((nonnull(1)));
bool create_page_entry_2m(pt_t *pt4, uint64_t _virt, uint64_t _phys, int flag, struct task *owner)__attribute__((nonnull(1)));
bool create_page_entry_4k(pt_t *pt4, uint64_t _virt, uint64_t _phys, int flag, struct task *owner)__attribute__((nonnull(1)));
unsigned long get_phys_address(const pt_t *pd, uint64_t _virt);
pe_t *get_pe(pt_t *pd, uint64_t _virt);
void clone_mm(pt_t *old_pt4, pt_t *new_pt4, void *owner, bool cow_existing)__attribute__((nonnull(1,2)));
void print_mm(const pt_t *pt4)__attribute__((nonnull));
void free_mm(pt_t *pt4)__attribute__((nonnull));
uint64_t get_pe_size(const pt_t *pd, uint64_t _virt);
int grow_page(struct task *ctsk, void *addr, pt_t *pt)__attribute__((nonnull(3)));

#define PGSIZE_4K	(1024*4)
#define	PGSIZE_2M	(1024*1024*2)
#define	PGSIZE_1G	(1024*1024*1024)
#define	PAGE_SIZE	PGSIZE_4K

#endif
// vim: set ft=c:
