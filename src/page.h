#ifndef _PAGE_H
#define _PAGE_H

#define TABLE_ENTRIES	512
#define	PAGE_SIZE	0x1000

typedef struct {
	unsigned	offset:12;
	unsigned	pml1_offset:9;
	unsigned	pml2_offset:9;
	unsigned	pml3_offset:9;
	unsigned	pml4_offset:9;
	unsigned	sign_extend:16;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
kb_pe;

typedef struct {
	unsigned	offset:21;
	unsigned	pml2_offset:9;
	unsigned	pml3_offset:9;
	unsigned	pml4_offset:9;
	unsigned	sign_extend:16;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
mb_pe;

typedef struct {
	unsigned	offset:30;
	unsigned	pml3_offset:9;
	unsigned	pml4_offset:9;
	unsigned	sign_extend:16;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
gb_pe;

typedef union {
	kb_pe k;
	mb_pe m;
	gb_pe g;
	uint64 addr;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
v_addr;

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
#define	PEF_NX		0x400

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

	uint64		base:40;		// 12,..,50; for lowest PML 12=pat

	unsigned	avail:11;		// 51,..,62

	unsigned	nx:1;			// 63
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
pe_t;

#define PT_SIZE	512

typedef union { 
	pe_t table_pe[PT_SIZE]; 
	uint64 table_u64[PT_SIZE];
}  
#ifdef __GNUC__
__attribute__((packed))
#endif
pt_t;

#define GET_PTP(x)      (pt_t *)((uint64)(x)->base << 12)
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

bool create_page_entry_1g(pt_t *pt4, uint64 _virt, uint64 _phys, int flag, struct task *owner);
bool create_page_entry_2m(pt_t *pt4, uint64 _virt, uint64 _phys, int flag, struct task *owner);
bool create_page_entry_4k(pt_t *pt4, uint64 _virt, uint64 _phys, int flag, struct task *owner);
unsigned long get_phys_address(pt_t *pd, uint64 _virt);
pe_t *get_pe(pt_t *pd, uint64 _virt);
void clone_mm(pt_t *old_pt4, pt_t *new_pt4, void *owner);
void print_mm(pt_t *pt4);
uint64 get_pe_size(pt_t *pd, uint64 _virt);
uint64 grow_page(struct task *ctsk, uint64 addr, pt_t *pt);

#define PGSIZE_4K	(1024*4)
#define	PGSIZE_2M	(1024*1024*2)
#define	PGSIZE_1G	(1024*1024*1024)

#endif
