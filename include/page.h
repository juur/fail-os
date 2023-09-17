#ifndef _PAGE_H
#define _PAGE_H

#include <ktypes.h>

#define KERN_MEM (64ULL*0x1000000ULL)

#define TABLE_ENTRIES   512

typedef struct {
    unsigned    offset:12;
    unsigned    pml1_offset:9;
    unsigned    pml2_offset:9;
    unsigned    pml3_offset:9;
    unsigned    pml4_offset:9;
    unsigned    sign_extend:16;
} __attribute__((packed)) kb_pe;

typedef struct {
    unsigned    offset:21;
    unsigned    pml2_offset:9;
    unsigned    pml3_offset:9;
    unsigned    pml4_offset:9;
    unsigned    sign_extend:16;
} __attribute__((packed)) mb_pe;

typedef struct {
    unsigned    offset:30;
    unsigned    pml3_offset:9;
    unsigned    pml4_offset:9;
    unsigned    sign_extend:16;
} __attribute__((packed)) gb_pe;

typedef struct {
    unsigned      _ign0:3;
    unsigned      pwt:1;
    unsigned      pcd:1;
    unsigned      _ign1:7;
    unsigned long addr:39; /* Assumes 52bit MAXPHYADDR */
    unsigned      _res0:12;
} __attribute__((packed)) cr3_pml45_t;

typedef union {
    kb_pe k;
    mb_pe m;
    gb_pe g;
    void *addr;
} __attribute__((packed)) v_addr;

#define PEF_P       (1<<0)
#define PEF_W       (1<<1)
#define PEF_U       (1<<2)
#define PEF_PWT     (1<<3)
#define PEF_PCD     (1<<4)
#define PEF_A       (1<<5)
#define PEF_D       (1<<6)
#define PEF_PTEPAT  (1<<7)
#define PEF_LAST    (1<<7)
#define PEF_PS      (1<<7)
#define PEF_G       (1<<8)
#define PEF_COW     (1<<9)
#define PEF_AVL1    (1<<10)
#define PEF_AVL2    (1<<11)
#define PEF_OTHPAT  (1<<12)

/* only used internally */
#define PEF_NO_ALLOC (1<<30)

#define PEF_NX      (1<<64)

typedef struct {
    unsigned    present:1;      // 0
    unsigned    write:1;        // 1
    unsigned    user:1;         // 2
    unsigned    pwt:1;          // 3
    unsigned    pcd:1;          // 4
    unsigned    access:1;       // 5
    unsigned    dirty:1;        // 6
    unsigned    last:1;         // 7 for a PML3/PML2 a 1 means no more PMLs
                                // otherwise is pat. Also known as PS

    unsigned    global:1;       // 8
    unsigned    cow:1;          // 9: 1 bit of AVL
    unsigned    avl:2;          // 10,11: 2 free bits i AVL

    uint64_t    base:40;        // 12,..,50; for lowest PML 12=pat

    unsigned    avail:11;       // 51,..,62

    unsigned    nx:1;           // 63
} __attribute__((packed)) pe_t;

#define PT_SIZE 512

typedef union {
    pe_t     table_pe[PT_SIZE];
    uint64_t table_u64[PT_SIZE];
} __attribute__((packed)) pt_t;


#define GET_PTP(x)      (pt_t *)((uintptr_t)(x)->base << 12)
#define SET_PTP(x,y)    ((x)->base = ((y) >> 12))

#define GET_PE(x,y,z)   (&(x)->table_pe[(y).k.z])
#define GET_PE_N(x,y)   (&(x)->table_pe[(y)])

#define GET_PHYS(x,y,z) (((x)->base << 12) + (z).y.offset)
#define GET_PHYS_K(x,y) (((x)->base << 12) + (y).k.offset)
#define GET_PHYS_M(x,y) (((x)->base << 12) + (y).m.offset)
#define GET_PHYS_G(x,y) (((x)->base << 12) + (y).g.offset)
/* FIXME: */
#define SET_PHYS(x,y)   ((x)->base = ((y) >> 12) & 0xffffffff)
#define SET_PHYS_K(x,y) ((x)->base = ((y) >> 12) & 0xffffffff)
#define SET_PHYS_M(x,y) ((x)->base = ((y) >> 12) & 0xffffffff)
#define SET_PHYS_G(x,y) ((x)->base = ((y) >> 12) & 0xffffffff)

#define GET_VIRT(a,b,c,d)   (d<<12|c<<21|b<<30|a<<39)

struct task;

#define PGSIZE_4K   (1024U*4U)
#define PGSIZE_2M   (1024U*1024U*2U)
#define PGSIZE_1G   (1024U*1024U*1024U)
#define PAGE_SIZE   PGSIZE_4K

typedef struct virtual_page_table vpt_t;

typedef union {
    pe_t     pe;
    vpt_t   *vpt;
    uint64_t raw;
} __attribute__((packed)) pt_entry;

/* manual sync between entries[x] and (pe_t *)pt_addr[x] */
struct virtual_page_table {
    vpt_t       *entries[PT_SIZE];  /* NULL = present=0 */
    struct task *owner;             /* NULL for kernel  */
    vpt_t       *parent;            /* NULL for PML4    */
    pt_t        *pt;                /* mapped           */
    uintptr_t    pt_addr;           /* can be 0         */
    int          level;             /* LVL_x            */
};

//#define LVL_PML5  5
#define LVL_PML4    4
#define LVL_PDPT    3
#define LVL_PD      2
#define LVL_PT      1


extern bool _create_page_entry_1g(pt_t *pt4, const void *_virt, const void *_phys, int flag, pid_t owner, const char *, const char *, int) __attribute__((nonnull(1), warn_unused_result));
extern bool _create_page_entry_2m(pt_t *pt4, const void *_virt, const void *_phys, int flag, pid_t owner, const char *, const char *, int) __attribute__((nonnull(1), warn_unused_result));
extern bool _create_page_entry_4k(pt_t *pt4, const void *_virt, const void *_phys, int flag, pid_t owner, const char *, const char *, int) __attribute__((nonnull(1), warn_unused_result));
#define create_page_entry_1g(pt,v,ph,f,o) _create_page_entry_1g((pt),(v),(ph),(f),(o),__FILE__,__func__,__LINE__)
#define create_page_entry_2m(pt,v,ph,f,o) _create_page_entry_2m((pt),(v),(ph),(f),(o),__FILE__,__func__,__LINE__)
#define create_page_entry_4k(pt,v,ph,f,o) _create_page_entry_4k((pt),(v),(ph),(f),(o),__FILE__,__func__,__LINE__)

extern uintptr_t get_phys_address(const pt_t *pd, const void *_virt) __attribute__((nonnull(1), access(read_only, 1), warn_unused_result));
extern size_t unmap(pt_t *pd, const void *virt, size_t len) __attribute__((nonnull(1)));
#define unmap(p,v,l) _unmap((p),(v),(l),__FILE__,__func__,__LINE__)

extern bool _unmap_region(const struct task *, const void *, size_t, pt_t *, const char *, const char *, int) __attribute__((nonnull(1)));
#define unmap_region(t,v,l,o) _unmap_region((t),(v),(l),(o),__FILE__,__func__,__LINE__)

extern pe_t *get_pe(pt_t *pd, const void *_virt) __attribute__((nonnull, warn_unused_result));
extern int clone_mm(pt_t *old_pt4, pt_t *new_pt4, pid_t owner, bool cow_existing)__attribute__((nonnull(1,2),warn_unused_result));
extern void print_mm(const pt_t *pt4)__attribute__((nonnull));
extern void free_mm(pt_t *pt4)__attribute__((nonnull));
extern int64_t get_pe_size(const pt_t *pd, const void *_virt);
extern int _grow_page(struct task *ctsk, void *addr, pt_t *pt, const char *, const char *, int line)__attribute__((nonnull(3), warn_unused_result));
#define grow_page(t,a,p) _grow_page((t),(a),(p),__FILE__,__func__,__LINE__)

extern bool _map_region(const struct task *const tsk, const void *virt, const void *phys, size_t len, int flags, pt_t *opt_pd, const char *, const char *, int)__attribute__((warn_unused_result));
#define map_region(t,v,p,l,f,o) _map_region((t),(v),(p),(l),(f),(o),__FILE__,__func__,__LINE__)

extern void free_pd(pt_t *pt);
extern pt_t *alloc_pd(const struct task *tsk)__attribute__((malloc(free_pd, 1), access(read_only, 1), warn_unused_result));
extern bool dupe_mm(const pt_t *old_pt4, pt_t *new_pt4, pid_t owner) __attribute__((nonnull(1,2)));
extern void *_add_kernel_mapping(void *phys, size_t length, const char *, const char *, int);
#define add_kernel_mapping(p, l) _add_kernel_mapping((p),(l),__FILE__,__func__,__LINE__)

extern vpt_t *new_vpt(void *phys_pd, const vpt_t *parent)__attribute__((warn_unused_result));


extern pt_t *kernel_pd;
#ifdef BACKUP_PD
extern pt_t *backup_kernel_pd;
#endif
#endif
// vim: set ft=c:
