#define _PAGE_C
#include <klibc.h>
#include <page.h>
#include <mem.h>
#include <cpu.h>
#include <frame.h>
#include <proc.h>

pt_t *kernel_pd;
pt_t *backup_kernel_pd;

__attribute__((nonnull))
static void decode_flags(const pe_t *const pe)
{
    printf("%c%c%c%c%c%c%c%c%02x",
            pe->present  ? 'P' : '_',
            pe->write    ? 'w' : 'r',
            pe->user     ? 'u' : 's',
            pe->access   ? 'a' : '_',
            pe->dirty    ? 'd' : '_',
            pe->last     ? 'L' : '_',
            pe->global   ? 'G' : '_',
            pe->cow      ? 'c' : '_',
            pe->avl
          );
}


__attribute__((nonnull))
void print_mm(const pt_t *restrict const pt4)
{
    uint64_t i,j,k,m;
    uint64_t addr;
    const pt_t *pt3,*pt2,*pt1;
    const pe_t *pe4,*pe3,*pe2,*pe1;

    /*
    printf("sizeof(kb_pe)  = 0x%lx\n", sizeof(kb_pe));
    printf("sizeof(mb_pe)  = 0x%lx\n", sizeof(mb_pe));
    printf("sizeof(gb_pe)  = 0x%lx\n", sizeof(gb_pe));
    printf("sizeof(pt_t)   = 0x%lx\n", sizeof(pt_t));
    printf("sizeof(pe_t)   = 0x%lx\n", sizeof(pe_t));
    printf("sizeof(v_addr) = 0x%lx\n", sizeof(v_addr));
    printf("sizeof(pt_t.table_pe)    = 0x%lx\n", sizeof(pe_t) * PT_SIZE);
    printf("sizeof(pt_t.table_u64)   = 0x%lx\n", sizeof(uint64_t) * PT_SIZE);
    */

    const pt_t *const current = get_cr3();

    printf("PML4: @ %p", (void *)pt4);

    if (!get_pe_size(current, pt4)) {
        printf("print_mm: PML4 not mapped, can't read\n");
        return;
    }

    //if (!get_pe_size(pt4, (uintptr_t)pt4)) printf(" !READ [%p]", (void *)pt4);

    for(i=0;i<PT_SIZE;i++) /* PML4 */
    {
        pe4 = GET_PE_N(pt4,i);
        if (!get_pe_size(current, pe4)) {
            printf("\nPML4E[%03lx]:  Unable to read\n", i);
            continue;
        }
        pt3 = GET_PTP(pe4);

        if (pe4->present) {
            printf("\nPML4E[%03lx]:  PDPT     @  %8lx:     ", i, (uintptr_t)pt3);
            decode_flags(pe4);
            printf(" = %0lx [%0lx]", pt4->table_u64[i], pt4->table_u64[i] & ~(PGSIZE_4K-1));
            //if (!get_pe_size(pt4, (uintptr_t)pt3)) printf(" !READ [%p]", (void *)pt3);

            for(j=0;j<PT_SIZE;j++) /* PML3(PDPT) */
            {
                pe3 = GET_PE_N(pt3, j);
                if (!get_pe_size(current, pe3)) {
                    printf("\n PDPTE[%03lx]: unable to read: %8lx", j, (uintptr_t)pe3);
                    continue;
                }

                pt2 = GET_PTP(pe3);

                if(pe3->present && pe3->last) {

                    addr = (uint64_t)GET_PTP(pe3);
                    printf("\n PDPTE[%03lx]: %8lx => %8lx: 1G: ",
                            j, GET_VIRT(i,j,0,0), addr);
                    decode_flags(pe3);
                    printf(" = %0lx [%0lx]", pt3->table_u64[j], pt3->table_u64[j] & ~(PGSIZE_1G-1));
                    //if (!get_pe_size(pt4, (uintptr_t)pt2)) {
                    //  printf(" !READ [%p]", (void *)pt2);
                    //}

                } else if(pe3->present) {

                    printf("\n PDPTE[%03lx]: PD       @  %8lx:     ", j, (uintptr_t)pt2);
                    decode_flags(pe3);
                    printf(" = %0lx [%0lx]", pt3->table_u64[j], pt3->table_u64[j] & ~(PGSIZE_4K-1));
                    //if (!get_pe_size(pt4, (uintptr_t)pt2)) printf(" !READ [%p]", (void *)pt2);

                    for(k=0;k<PT_SIZE;k++) /* PML2(PD) */
                    {
                        pe2 = GET_PE_N(pt2, k);
                        if (!get_pe_size(current, pe2)) {
                            printf("\n  PDE[%03lx]: unable to read: %8lx", k, (uintptr_t)pe2);
                            k = PT_SIZE;
                            continue;
                        }
                        pt1 = GET_PTP(pe2);

                        if(pe2->present && pe2->last) {

                            printf("\n  PDE[%03lx]:  %8lx => %8lx: 2M: ",
                                    k, GET_VIRT(i,j,k,0), (uintptr_t)pt1);
                            decode_flags(pe2);
                            printf(" = %0lx [%0lx]", pt2->table_u64[k], pt2->table_u64[k] & ~(PGSIZE_2M-1));
                            //if (!get_pe_size(pt4, (uintptr_t)pe2)) printf(" !READ [%p]", (void *)pe2);

                        } else if(pe2->present) {

                            printf("\n  PDE[%03lx]:  PT       @  %8lx:     ", k, (uintptr_t)pt1);
                            decode_flags(pe2);
                            printf(" = %0lx [%0lx]", pt2->table_u64[k], pt2->table_u64[k] & ~(PGSIZE_4K-1));
                            //if (!get_pe_size(pt4, (uintptr_t)pe2)) printf(" !READ [%p]", (void *)pt1);

                            for(m=0;m<PT_SIZE;m++) /* PML1(PT) */
                            {
                                pe1 = GET_PE_N(pt1, m);
                                if (!get_pe_size(current, pe1)) {
                                    printf("\n   PTE[%03lx]: unable to read: %8lx", m, (uintptr_t)pe1);
                                    m = PT_SIZE;
                                    k = PT_SIZE;
                                    continue;
                                }
                                addr = (uint64_t)GET_PTP(pe1);
                                if(!pe1->present)
                                    continue;

                                printf("\n   PTE[%03lx]: %8lx => %8lx: 4k: ", m, GET_VIRT(i,j,k,m), addr);
                                decode_flags(pe1);
                                printf(" = %0lx [%0lx]", pt1->table_u64[m], pt1->table_u64[m] & ~(PGSIZE_4K-1));
                                //if (!get_pe_size(pt4, (uintptr_t)pe1)) printf(" !READ [%p]", (void *)pe1);
                            } /* PML1 */
                        }
                    } /* PML2 */

                }
            } /* PML3 */
        }
    } /* PML4 */
    printf("\n");
}

/* FIXME this has problems: a) lack of identity mapping in the current CR3 means
 * it can't edit the page entries/table. b) if anything is shared, boom */
#if 0
__attribute__((nonnull))
void free_mm(pt_t *const pt4)
{
    printf("free_mm: %p", (void *)pt4);
    while(1) hlt();

    uint64_t i,k,j;//,m;
    pt_t *pt3,*pt2,*pt1;
    pe_t *pe4,*pe3,*pe2;//,*pe1;

    for(i=0;i<PT_SIZE;i++) /* PML4E[] */
    {
        pe4 = GET_PE_N(pt4,i);
        pt3 = GET_PTP(pe4);
        if(pe4->present) {
            for(j=0;j<PT_SIZE;j++) /* PML3E[] */
            {
                pe3 = GET_PE_N(pt3, j);
                pt2 = GET_PTP(pe3);
                if(pe3->present && pe3->last) { /* 1GiB page */
                    pe3->present = 0;
                } else if(pe3->present) {
                    for(k=0;k<PT_SIZE;k++) /* PML2E[] */
                    {
                        pe2 = GET_PE_N(pt2, k);
                        pt1 = GET_PTP(pe2);
                        if(pe2->present && !pe2->last) {
                            memset(pt1, 0, sizeof(pt_t));
                            clear_frame((void *)pt1); /* 4KiB page */
                        }
                        pe2->present = 0;
                    }
                    clear_frame((void *)pt2);
                    pe3->present = 0;
                }
            }
            clear_frame((void *)pt3);
            pe4->present = 0;
        }
    }

    free_pd(pt4);
    clear_frame((void *)pt4);
}
#endif


#if 0
__attribute__((nonnull))
bool dupe_mm(const pt_t *old_pt4, pt_t *new_pt4, pid_t owner)
{
    int i,j,k,m;

    //printf("dupe_mm: %p -> %p\n", (void *)old_pt4, (void *)new_pt4);

    pt_t *new_pt3, *new_pt2, *new_pt1;
    pe_t *new_pe4, *new_pe3, *new_pe2, *new_pe1;
    const pt_t *old_pt3, *old_pt2, *old_pt1;
    const pe_t *old_pe4, *old_pe3, *old_pe2, *old_pe1;

    *new_pt4 = *old_pt4;
    pt_t *cr3 = get_cr3();
    //printf("dupe_mm: pt4 copied\n");
    //memcpy(new_pt4, old_pt4, sizeof(pt_t));

    for (i=0;i<PT_SIZE;i++) /* clone PML4 */
    {
        //printf("pt3[%x]", i);
        old_pe4 = GET_PE_N(old_pt4, i);
        new_pe4 = GET_PE_N(new_pt4, i);

        if (old_pe4->present) {
            old_pt3 = GET_PTP(old_pe4);
            if (!is_useable((void *)old_pt3)) {
                printf("dupe_mm: PML4E[%3x]: unuseable\n", i);
                continue;
            }
            new_pt3 = (pt_t *)find_frame(owner);
            if (!new_pt3)
                goto fail_pt3;

            /*
            if (!get_pe_size(new_pt4, (uintptr_t)new_pt3))
                map_region(owner, (uintptr_t)new_pt3, (uintptr_t)new_pt3, PAGE_SIZE,
                        PEF_P|PEF_W, new_pt4);
                        */

            if (!get_pe_size(cr3, new_pt3))
                printf("***\ndupe_mm: no mapping for new_pt3=%p\n***\n", (void *)new_pt3);

            memset(new_pt3, 0, PAGE_SIZE);
            *new_pt3 = *old_pt3;
            //printf(" copied\n");
            SET_PTP(new_pe4, (uint64_t)new_pt3);

            for(j=0;j<PT_SIZE;j++) /* clone PML3 */
            {
                //printf("pt2[%x.%x]", i, j);
                old_pe3 = GET_PE_N(old_pt3, j);
                new_pe3 = GET_PE_N(new_pt3, j);
                //printf(" %c%c",
                //      old_pe3->present ? 'P' : '.',
                //      old_pe3->last    ? 'L' : '.');

                if (old_pe3->present && old_pe3->last) {    /* 1G pte */
                    *new_pe3 = *old_pe3;
                    //printf(" copied 1G\n");
                } else if (old_pe3->present) { /* 2M/4k pt */
                    old_pt2 = GET_PTP(old_pe3);
                    if (!is_useable((void *)old_pt2)) {
                        printf("dupe_mm: PDPTE[%3x]: unuseable\n", j);
                        continue;
                    }
                    new_pt2 = (pt_t *)find_frame(owner);
                    if (!new_pt2)
                        goto fail_pt2;

                    //printf(" new_pt2=%p", new_pt2);

                    /*
                    if (!get_pe_size(new_pt4, (uintptr_t)new_pt2))
                        map_region(owner, (uintptr_t)new_pt2, (uintptr_t)new_pt2, PAGE_SIZE,
                                PEF_P|PEF_W, new_pt4);
                                */
                    if (!get_pe_size(cr3, new_pt2))
                        printf("***\ndupe_mm: no mapping for new_pt2=%p\n***\n", (void *)new_pt2);

                    memset(new_pt2, 0, PAGE_SIZE);
                    *new_pt2 = *old_pt2;
                    SET_PTP(new_pe3, (uint64_t)new_pt2);

                    for (k=0;k<PT_SIZE;k++) /* clone PML2 */
                    {
                        //printf("pt1[%x.%x.%x]", i, j, k);
                        old_pe2 = GET_PE_N(old_pt2, k);
                        new_pe2 = GET_PE_N(new_pt2, k);

                        if (old_pe2->present && old_pe2->last) { /* 2M pte */
                            *new_pe2 = *old_pe2;
                            //printf(" copied 2M\n");
                        } else if(old_pe2->present && !old_pe2->last) { /* 4k pt */
                            old_pt1 = GET_PTP(old_pe2);
                            if (!is_useable((void *)old_pt1)) {
                                printf("dupe_mm: PDE[%3x]: unuseable\n", k);
                                continue;
                            }

                            new_pt1 = (pt_t *)find_frame(owner);
                            if (!new_pt1)
                                goto fail_pt1;

                            /*
                            if (!get_pe_size(new_pt4, (uintptr_t)new_pt1))
                                map_region(owner, (uintptr_t)new_pt1, (uintptr_t)new_pt1, PAGE_SIZE,
                                        PEF_P|PEF_W, new_pt4);
                                        */

                            if (!get_pe_size(cr3, new_pt1))
                                printf("***\ndupe_mm: no mapping for new_pt1=%p\n***\n", (void *)new_pt1);
                            memset(new_pt1, 0, PAGE_SIZE);
                            *new_pt1 = *old_pt1;
                            //printf("pt1[%x.%x.%x] copied\n", i, j, k);
                            SET_PTP(new_pe2, (uint64_t)new_pt1);

                            for (m=0;m<PT_SIZE;m++) /* clone PML1 */
                            {
                                old_pe1 = GET_PE_N(old_pt1, m);
                                new_pe1 = GET_PE_N(new_pt1, m);

                                *new_pe1 = *old_pe1;
                                //printf("pe1[%x.%x.%x.%x] copied 4k\n", i, j, k, m);
                            } /* PML1[] */
                        } else {
                            //printf("\n");
                        }
                    } /* PML2[] */
                } else {
                    //printf("\n");
                }
            } /* PML3[] */
        } else {
            //printf("\n");
        }
    } /* PML4[] */

    //printf("dupe_mm: done\n");

    return true;

fail_pt1:
fail_pt2:
fail_pt3:
    printf("dupe_mm: failed to allocate memory\n");
    return false;

}
#endif

int clone_mm(pt_t *const old_pt4, pt_t *const new_pt4, pid_t owner, const bool cow_existing)
{
    int i,j,k,m;

    //printf("clone_mm: %p -> %p pid=%d cow=%d\n",
      //      (void *)old_pt4, (void *)new_pt4, owner, cow_existing);

    pt_t *new_pt3, *new_pt2, *new_pt1;
    pe_t *new_pe4, *new_pe3, *new_pe2, *new_pe1;
    pt_t *old_pt3, *old_pt2, *old_pt1;
    pe_t *old_pe4, *old_pe3, *old_pe2, *old_pe1;
    const pt_t *cr3 = get_cr3();

    *new_pt4 = *old_pt4;

    for(i=0;i<PT_SIZE;i++) /* clone PML4 */
    {
        old_pe4 = GET_PE_N(old_pt4, i);
        new_pe4 = GET_PE_N(new_pt4, i);

        if(old_pe4->present) {
            new_pt3 = (pt_t *)find_frame(owner);
            if(!new_pt3) goto fail_pt3;

            if (!get_pe_size(cr3, new_pt3)) {
                printf("***\nclone_mm: no mapping for new_pt3=%p\n***\n", (void *)new_pt3);
                print_mm(cr3);
                goto fail_pt3;
            }
            memset(new_pt3, 0, PAGE_SIZE);

            old_pt3 = GET_PTP(old_pe4);
            *new_pt3 = *old_pt3;
            SET_PTP(new_pe4, (uint64_t)new_pt3);

            for(j=0;j<PT_SIZE;j++) /* clone PML3 */
            {
                old_pe3 = GET_PE_N(old_pt3, j);
                new_pe3 = GET_PE_N(new_pt3, j);
                *new_pe3 = *old_pe3;

                if(old_pe3->present && old_pe3->user && old_pe3->last) {    /* 1G pte */
                    //printf("clone_mm: old_pe3: %p\n", (void *)GET_PTP(old_pe3));
                    /* increase the lock count */
                    set_n_frames((void *)GET_PTP(old_pe2), PGSIZE_1G/PGSIZE_4K);

                    new_pe3->write  = 0;
                    new_pe3->cow    = 1;
                    new_pe3->global = 0;
                    new_pe3->user   = 1;
                    new_pe3->last   = 1;
                    if (cow_existing) {
                        old_pe3->write = 0;
                        old_pe3->cow = 1;
                    }
                } else if(old_pe3->present && !old_pe3->last) { /* 2M/4k pt */
                    new_pt2 = (pt_t *)find_frame(owner);
                    if(!new_pt2) goto fail_pt2;
                    if (!get_pe_size(cr3, new_pt2)) {
                        printf("***\nclone_mm: no mapping for new_pt2=%p\n***\n", (void *)new_pt2);
                        print_mm(cr3);
                        goto fail_pt2;
                    }
                    memset(new_pt2, 0, PAGE_SIZE);

                    old_pt2 = GET_PTP(old_pe3);
                    *new_pt2 = *old_pt2;
                    SET_PTP(new_pe3, (uint64_t)new_pt2);

                    for(k=0;k<PT_SIZE;k++) /* clone PML2 */
                    {
                        old_pe2 = GET_PE_N(old_pt2, k);
                        new_pe2 = GET_PE_N(new_pt2, k);
                        *new_pe2 = *old_pe2;

                        if(old_pe2->present && old_pe2->user && old_pe2->last) { /* 2M pte */
                            //printf("clone_mm: old_pe2: %p\n", (void *)GET_PTP(old_pe2));
                            /* increase the lock count */
                            set_n_frames((void *)GET_PTP(old_pe2), PGSIZE_2M/PGSIZE_4K);

                            new_pe2->write  = 0;
                            new_pe2->cow    = 1;
                            new_pe2->global = 0;
                            new_pe2->last   = 1;
                            new_pe2->user   = 1;
                            if (cow_existing) {
                                old_pe2->write = 0;
                                old_pe2->cow = 1;
                            }
                        } else if(old_pe2->present && !old_pe2->last) { /* 4k pt */
                            new_pt1 = (pt_t *)find_frame(owner);
                            if(!new_pt1) goto fail_pt1;
                            if (!get_pe_size(cr3, new_pt1)) {
                                printf("***\nclone_mm: no mapping for new_pt1=%p\n***\n", (void *)new_pt1);
                                print_mm(cr3);
                                goto fail_pt1;
                            }
                            memset(new_pt1, 0, PAGE_SIZE);

                            old_pt1 = GET_PTP(old_pe2);
                            *new_pt1 = *old_pt1;
                            SET_PTP(new_pe2, (uint64_t)new_pt1);

                            for(m=0;m<PT_SIZE;m++) /* clone PML1 */
                            {
                                old_pe1 = GET_PE_N(old_pt1, m);
                                new_pe1 = GET_PE_N(new_pt1, m);
                                *new_pe1 = *old_pe1;

                                if(old_pe1->present && old_pe1->user) {
                                    //printf("clone_mm: old_pe1: %p\n", (void *)GET_PTP(old_pe1));
                                    /* increase the lock count */
                                    set_frame((void *)GET_PTP(old_pe1));

                                    new_pe1->write  = 0;
                                    new_pe1->cow    = 1;
                                    new_pe1->global = 0;
                                    new_pe1->user   = 1;
                                    if(cow_existing) {
                                        old_pe1->write = 0;
                                        old_pe1->cow = 1;
                                    }
                                }
                            } /* PML1 */
                        }
                    } /* PML2 */
                }
            } /* PML3 */
        }
    } /* PML4 */

    return 0;

fail_pt1:
fail_pt2:
fail_pt3:
    printf("clone_mm: failed to allocate memory\n");
    return -1;
}

__attribute__((nonnull))
bool _create_page_entry_1g(pt_t *const pt4, const void *_virt,
        const void *_phys, const int flag, pid_t owner, const char *file,
        const char *func, int line)
{
    v_addr virt;
    pe_t *pe4, *pe3;
    pt_t *pt3;
    bool fail = false;

    //printf("create_page_entry_1g: pt=0x%p %p -> %p: %s:%s:%u\n",
    //        (void *)pt4, _virt, _phys, file, func, line);
    if (_virt != (void *)((uintptr_t)_virt & ~0x3fffffffUL)) {
        printf("create_page_entry_1g: misaligned virtual address: %p\n", _virt);
        fail = true;
    }
    if (_phys != (void *)((uintptr_t)_phys & ~0x3fffffffUL)) {
        printf("create_page_entry_1g: misaligned phys address: %p\n", _phys);
        fail = true;
    }

    if (fail) {
        return false;
    }

    virt.addr = (void *)((uintptr_t)_virt & ~0x3fffffffUL);

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if (!pe4->present) {
        uintptr_t tmp = (uintptr_t)find_frame(owner);
        if (!tmp)
            goto pg_fail;
        memset((void *)tmp, 0, PAGE_SIZE);

        SET_PTP(pe4, tmp);
        pe4->present = 1;
        pt3 = (pt_t *)tmp;

        /*
        if ( (flag & PEF_NO_ALLOC) == 0 && get_pe_size(pt4, tmp) == 0)
            create_page_entry_4k(pt4, tmp, tmp, PEF_W|PEF_P, owner);
            */
        memset((void *)tmp, 0, PAGE_SIZE);
    } else {
        pt3 = GET_PTP(pe4);
    }
    if (flag & PEF_U) pe4->user = 1;
    if (flag & PEF_W) pe4->write = 1;

    pe3 = GET_PE(pt3,virt,pml3_offset);
    if(pe3->present) {
        printf("create_page_entry_1g: pe3 already present virt=%p phys=%p\n", _virt, _phys);
        return false;
    }

    SET_PHYS_G(pe3,(uintptr_t)_phys & ~0x3fffffffUL);
    if(flag & PEF_P) pe3->present = 1;
    if(flag & PEF_U) pe3->user = 1;
    if(flag & PEF_W) pe3->write = 1;
    if(flag & PEF_G) pe3->global = 1;
    pe3->last = 1;

    return true;
pg_fail:
    printf("create_page_entry_1g: failed\n");
    return false;
}

__attribute__((nonnull))
bool _create_page_entry_2m(pt_t *const pt4, const void *_virt,
        const void *_phys, const int flag, pid_t owner, const char *file,
        const char *func, int line)
{
    v_addr virt;
    pe_t *pe4, *pe3, *pe2;
    pt_t *pt3, *pt2;
    uintptr_t tmp;
    bool fail = false;

    //printf("create_page_entry_2m: pt=0x%p %p -> %p flag=%x: %s:%s:%u\n",
      //      (void *)pt4, _virt, _phys, flag, file, func, line);

    if (_virt != (void *)((uintptr_t)_virt & ~0x1fffffUL)) {
        printf("create_page_entry_2m: misaligned virtual address: %p\n", _virt);
        fail = true;
    }
    if (_phys != (void *)((uintptr_t)_phys & ~0x1fffffUL)) {
        printf("create_page_entry_2m: misaligned phys address: %p\n", _phys);
        fail = true;
    }

    if (fail) {
        return false;
    }

    virt.addr = (void *)((uintptr_t)_virt & ~0x1fffffUL);

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if (!pe4->present) {
        tmp = (uintptr_t)find_frame(owner);
        if (!tmp)
            goto pg_fail;
        //printf("create_page_entry_2m: new pt3 allocated at %p\n", (void *)tmp);

        SET_PTP(pe4, tmp);
        pe4->present = 1;
        pe4->write   = 1;
        pt3 = (pt_t *)tmp;
        memset((void *)tmp, 0, PAGE_SIZE);

        /*
        if (!get_pe_size(pt4, tmp)) {
            printf("create_page_entry_4k: new pt3 mapping missing identity %s\n", !(flag & PEF_NO_ALLOC) ? "creating" : "");
            if ((flag & PEF_NO_ALLOC) == 0)
                create_page_entry_4k(pt4, tmp, tmp, PEF_W|PEF_P, owner);
        }
        */
    } else {
        pt3 = GET_PTP(pe4);
    }
    if (flag & PEF_U) pe4->user = 1;
    if (flag & PEF_W) pe4->write = 1;

    pe3 = GET_PE(pt3,virt,pml3_offset);
    if (pe3->last) {
        printf("create_page_entry_2m: attempt to overwrite a 1g page\n");
        return false;
    } else if (!pe3->present) {
        tmp = (uintptr_t)find_frame(owner);
        if (!tmp)
            goto pg_fail;
        //printf("create_page_entry_2m: new pt2 allocated at %p\n", (void *)tmp);

        SET_PTP(pe3, tmp);
        pe3->present = 1;
        pe3->write   = 1;
        pt2 = (pt_t *)tmp;
        memset((void *)tmp, 0, PAGE_SIZE);

        /*
        if (!get_pe_size(pt4, tmp)) {
            printf("create_page_entry_4k: new pt3 mapping missing identity %s\n", !(flag & PEF_NO_ALLOC) ? "creating" : "");
            if ((flag & PEF_NO_ALLOC) == 0)
                create_page_entry_4k(pt4, tmp, tmp, PEF_W|PEF_P, owner);
        }
        */
    } else {
        pt2 = GET_PTP(pe3);
    }
    if (flag & PEF_U) pe3->user = 1;
    if (flag & PEF_W) pe3->write = 1;

    pe2 = GET_PE(pt2,virt,pml2_offset);
    if(pe2->present) {
        printf("create_page_entry_2m: pe2 already present\n");
        return false;
    }

    SET_PHYS_M(pe2,(uintptr_t)_phys & ~0x1fffffUL);
    if(flag & PEF_P) pe2->present = 1;
    if(flag & PEF_U) pe2->user    = 1;
    if(flag & PEF_W) pe2->write   = 1;
    if(flag & PEF_G) pe2->global  = 1;
    pe2->last = 1;

    return true;

pg_fail:
    printf("create_page_entry_2m: failed\n");
    return false;
}

void *_add_kernel_mapping(void *phys, size_t length, const char *file, const char *func, int line)
{
    void *ret;

    //printf("add_kernel_mapping: %p[%lu]: %s:%s:%d\n", phys, length, file, func, line);

    if ((length % PGSIZE_4K) != 0) {
        printf("add_kernel_mapping: length not aligned\n");
        return 0UL;
    }

    if (((uintptr_t)phys % PGSIZE_4K) != 0) {
        printf("add_kernel_mapping: physical address not aligned\n");
        return 0UL;
    }

    if (((uintptr_t)kern_heap_top % PGSIZE_4K) != 0)
        kern_heap_top = (((uintptr_t)kern_heap_top + (PGSIZE_4K-1UL)) & ~(PGSIZE_4K-1UL));

    ret = (void *)kern_heap_top;
    if (!map_region(NULL, (void *)kern_heap_top, phys, length, PEF_P|PEF_W|PEF_G, kernel_pd)) {
        printf("add_kernel_mapping: map_region failed: %s:%s:%d\n", file, func, line);
        return 0UL;
    }
    if (!map_region(NULL, (void *)kern_heap_top, phys, length, PEF_P|PEF_W|PEF_G, backup_kernel_pd)) {
        printf("add_kernel_mapping: map_region failed: %s:%s:%d\n", file, func, line);
        return 0UL;
    }

    kern_heap_top += length;

    return ret;
}

vpt_t *new_vpt(void *phys_pd, const vpt_t *parent)
{
    vpt_t *ret;
    if ((ret = kmalloc(sizeof(vpt_t), "vpt", NULL, KMF_ZERO)) == NULL) {
        printf("RAM: unable to allocate ret\n");
        while(1) hlt();
    }

    if (parent) {
        if (parent->parent) {
            if (parent->parent->parent) {
                ret->level = LVL_PT;
            } else
                ret->level = LVL_PD;
        } else
            ret->level = LVL_PDPT;
    } else
        ret->level = LVL_PML4;

    ret->level   = LVL_PML4;
    ret->pt_addr = (uintptr_t)phys_pd;
    ret->pt      = (pt_t *)add_kernel_mapping(phys_pd, PGSIZE_4K);

    if (!ret->pt) {
        kfree(ret);
        return NULL;
    }

    return ret;
}


__attribute__((nonnull))
bool _create_page_entry_4k(pt_t *const pt4, const void *_virt,
        const void *_phys, const int flag, pid_t owner,
        const char *file, const char *func, int line)
{
    v_addr virt;
    pe_t *pe4, *pe3, *pe2, *pe1;
    pt_t *pt3, *pt2, *pt1;
    uintptr_t tmp;
    bool fail = false;

    //printf("create_page_entry_4k: pt=0x%p %p -> %p %s:%s:%u\n", (void *)pt4, _virt, _phys, file, func, line);

    if (_virt != (void *)((uintptr_t)_virt & ~0xfffUL)) {
        printf("create_page_entry_4k: misaligned virtual address: %p\n", _virt);
        fail = true;
    }
    if (_phys != (void *)((uintptr_t)_phys & ~0xfffUL)) {
        printf("create_page_entry_4k: misaligned phys address: %p\n", _phys);
        fail = true;
    }

    if (fail) {
        return false;
    }

    virt.addr = (void *)((uintptr_t)_virt & ~0xfffUL);

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if (!pe4->present) {
        tmp = (uintptr_t)find_frame(owner);
        if (!tmp)
            goto pg_fail;
        //printf("create_page_entry_4k: new pt3 allocated at %p\n", (void *)tmp);

        SET_PTP(pe4, tmp);
        pe4->present = 1;
        pe4->write   = 1;
        pt3 = (pt_t *)tmp;
        memset((void *)tmp, 0, PAGE_SIZE);

        /*
        if (!get_pe_size(pt4, tmp)) {
            printf("create_page_entry_4k: new pt3 mapping missing identity %s\n", !(flag & PEF_NO_ALLOC) ? "creating" : "");
            if ((flag & PEF_NO_ALLOC) == 0)
                create_page_entry_4k(pt4, tmp, tmp, PEF_W|PEF_P, owner);
        }
        */
    } else {
        pt3 = GET_PTP(pe4);
    }
    if (flag & PEF_U) pe4->user = 1;
    if (flag & PEF_W) pe4->write = 1;

    pe3 = GET_PE(pt3,virt,pml3_offset);
    if (pe3->last) {
        printf("create_page_entry_4k: attempt to overwrite a 1g page\n");
        return false;
    } else if(!pe3->present) {
        tmp = (uintptr_t)find_frame(owner);
        if (!tmp)
            goto pg_fail;
        //printf("create_page_entry_4k: new pt2 allocated at %p\n", (void *)tmp);

        SET_PTP(pe3, tmp);
        pe3->present = 1;
        pe3->write   = 1;
        pt2 = (pt_t *)tmp;
        memset((void *)tmp, 0, PAGE_SIZE);

        /*
        if (!get_pe_size(pt4, tmp)) {
            printf("create_page_entry_4k: new pt2 mapping missing identity %s\n", !(flag & PEF_NO_ALLOC) ? "creating" : "");
            if ((flag & PEF_NO_ALLOC) == 0)
                create_page_entry_4k(pt4, tmp, tmp, PEF_W|PEF_P, owner);
        }
        */
    } else {
        pt2 = GET_PTP(pe3);
    }
    if (flag & PEF_U) pe3->user = 1;
    if (flag & PEF_W) pe3->write = 1;

    pe2 = GET_PE(pt2,virt,pml2_offset);
    if (pe2->last) {
        printf("create_page_entry_4k: attempt to overwrite a 2m page\n");
        return false;
    } else if(!pe2->present) {
        tmp = (uintptr_t)find_frame(owner);
        if (!tmp)
            goto pg_fail;
        //printf("create_page_entry_4k: new pt1 allocated at %p\n", (void *)tmp);

        SET_PTP(pe2, tmp);
        pe2->present = 1;
        pe2->write   = 1;
        pe2->last    = 0;
        pt1 = (pt_t *)tmp;

        memset((void *)tmp, 0, PAGE_SIZE);
        /*
        if (!get_pe_size(pt4, tmp)) {
            printf("create_page_entry_4k: new pt1 mapping missing identity %s\n", !(flag & PEF_NO_ALLOC) ? "creating" : "");
            if ((flag & PEF_NO_ALLOC) == 0)
                create_page_entry_4k(pt4, tmp, tmp, PEF_W|PEF_P, owner);
        }
        */
    } else {
        pt1 = GET_PTP(pe2);
    }

    /* according to qemu source code, the protection bits are &= PML4E|PDPT|PD|PT */

    if (flag & PEF_U) pe2->user = 1;
    if (flag & PEF_W) pe2->write = 1;

    pe1 = GET_PE(pt1,virt,pml1_offset);
    if (pe1->present) {
        printf("create_page_entry_4k: pe1 already present: virt=%p [pt1=%p]\n", virt.addr, (void *)pt1);
        //print_mm(pt4);
        return false;
    }

    SET_PHYS_K(pe1, (uintptr_t)_phys & ~0xfffUL);
    if(flag & PEF_P) pe1->present = 1;
    if(flag & PEF_U) pe1->user    = 1;
    if(flag & PEF_W) pe1->write   = 1;
    if(flag & PEF_G) pe1->global  = 1;

    return true;

pg_fail:
    printf("create_page_entry_4k: failed\n");
    return false;
}

__attribute__((nonnull(1)))
pe_t *get_pe(pt_t *const pd, const void *_virt)
{
    const v_addr virt = {.addr = (void *)_virt };
    const pe_t *pe4;
    pe_t *pe3,*pe2,*pe1;
    const pt_t *pt4;
    pt_t *pt3,*pt2,*pt1;

    pt4 = pd;

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if(!pe4 || !pe4->present) return NULL;

    pt3 = GET_PTP(pe4);
    pe3 = GET_PE(pt3,virt,pml3_offset);
    if(!pe3 || !pe3->present) return NULL;
    if(pe3->last) return pe3;

    pt2 = GET_PTP(pe3);
    pe2 = GET_PE(pt2,virt,pml2_offset);
    if(!pe2 || !pe2->present) return NULL;
    if(pe2->last) return pe2;

    pt1 = GET_PTP(pe2);
    pe1 = GET_PE(pt1,virt,pml1_offset);
    if(!pe1->present) return NULL;
    return pe1;
}

__attribute__((nonnull))
int64_t get_pe_size(const pt_t *const pd, const void *_virt)
{
    v_addr virt;
    const pe_t *pe4,*pe3,*pe2,*pe1;
    const pt_t *pt4,*pt3,*pt2,*pt1;

    pt4 = pd;
    virt.addr = (void *)_virt;

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if(!pe4 || !pe4->present) return 0;

    pt3 = GET_PTP(pe4);
    pe3 = GET_PE(pt3,virt,pml3_offset);
    if(!pe3 || !pe3->present) return 0;
    if(pe3->last) return PGSIZE_1G;

    pt2 = GET_PTP(pe3);
    pe2 = GET_PE(pt2,virt,pml2_offset);
    if(!pe2 || !pe2->present) return 0;
    if(pe2->last) return PGSIZE_2M;

    pt1 = GET_PTP(pe2);
    pe1 = GET_PE(pt1,virt,pml1_offset);
    if(!pe1 || !pe1->present) return 0;

    return PGSIZE_4K;
}

/* its unclear to me if this should return void * (when the callee can't
 * use the physical address directly or uintptr_t */
__attribute__((nonnull(1)))
uintptr_t get_phys_address(const pt_t *const pd, const void *_virt)
{
    uintptr_t ret = 0;
    v_addr virt;
    const pe_t *pe4,*pe3,*pe2,*pe1;
    const pt_t *pt4,*pt3,*pt2,*pt1;

    pt4 = pd;
    virt.addr = (void *)_virt;

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if(!pe4 || !pe4->present) return -1UL;

    pt3 = GET_PTP(pe4);
    pe3 = GET_PE(pt3,virt,pml3_offset);
    if(!pe3 || !pe3->present) return -1UL;
    if(pe3->last) { // 1G entry
        ret = (uintptr_t)GET_PHYS_G(pe3,virt);
        goto end;
    }

    pt2 = GET_PTP(pe3);
    pe2 = GET_PE(pt2,virt,pml2_offset);
    if(!pe2 || !pe2->present) return -1UL;
    if(pe2->last) { // 2M entry
        ret = (uintptr_t)GET_PHYS_M(pe2,virt);
        goto end;
    }

    // 4k entry
    pt1 = GET_PTP(pe2);
    pe1 = GET_PE(pt1,virt,pml1_offset);
    if(!pe1 || !pe1->present) return -1UL;

    ret = (uintptr_t)GET_PHYS_K(pe1,virt);
end:
    return ret;
}

/*
__attribute__((nonnull))
void set_pe_in_pt(_Unused pt_t *pt, _Unused uint64_t virt, _Unused uint64_t phys, _Unused int present,
        _Unused int write, _Unused int user, _Unused int is_frame)
{
    // how to find out what PML1,2,3,4 we are for bitmasking?
    // call set_pe
}

void set_pe(pe_t *pe, uint64_t phys, int present, int write, int user, int is_global, bool clear)
{
    if (clear)
        *((uint64_t *)pe) = 0;
    if (is_global != -1)
        pe->global = (unsigned)is_global;
    if (write != -1)
        pe->write = (unsigned)write;
    if (user != -1)
        pe->user = (unsigned)user;
    if (present != -1)
        pe->present = (unsigned)present;
    if (phys != -1UL)
    pe->base = (phys & ~(PGSIZE_4K-1U)) >> 12U;
}
*/

int _grow_page(struct task *const ctsk, void *const addr, pt_t *const pt,
        const char *file, const char *func, int line)
{
    /*
    printf("grow_page: addr=%p pt=%p heap(%lx-%lx) stack(%lx-%lx) %s:%s:%u\n",
            addr, (void *)pt,
            ctsk->heap_start, ctsk->heap_end,
            ctsk->stack_start, ctsk->stack_end,
            file, func, line);
    */

    if( (addr > ctsk->heap_end || addr < ctsk->heap_start)
            && (addr > ctsk->stack_end || addr < ctsk->stack_start) ) {
        printf("grow_page: %p is outside %p:%p and %p:%p\n",
                (void *)addr,
                (void *)ctsk->heap_start, (void *)ctsk->heap_end,
                (void *)ctsk->stack_start, (void *)ctsk->stack_end
                );
        return -2;
    }
    if(!create_page_entry_4k(pt, (void *)((uintptr_t)addr & ~0xfffUL), find_frame(ctsk->pid),
            PEF_P|PEF_U|PEF_W, ctsk->pid))
        return -3;
    __asm__ volatile("invlpg %0"::"m"(addr));
    return 0;
}

__attribute__((nonnull))
void free_pd(pt_t *pt)
{
    printf("free_pd: %p\n", (void *)pt);
    clear_frame(pt);
}

__attribute__((malloc(free_pd,1)))
pt_t *alloc_pd(const struct task *tsk)
{
    pt_t *ret;

    if ((ret = find_frame(tsk->pid)) == NULL)
        return NULL;

    if (get_pe_size(get_cr3(), ret) != 0)
        memset(ret, 0, sizeof(PAGE_SIZE));

    return ret;
}

/* TODO len properly */
__attribute__((nonnull(1)))
size_t _unmap(pt_t *pd, const void *_virt, size_t len, const char *file,
        const char *func, int line)
{
    //printf("unmap: pd=%p _virt=%p len=%lu: %s:%s:%d\n", (void *)pd, _virt, len, file, func, line);

    v_addr virt;
    const pe_t *pe4,*pe3,*pe2,*pe1;
    const pt_t *pt4,*pt3,*pt2,*pt1;

    pt4 = pd;
    virt.addr = (void *)_virt;

    pe4 = GET_PE(pt4,virt,pml4_offset);
    if (!pe4 || !pe4->present) {
        printf("unmap: pe4 not present\n");
        return 0;
    }

    pt3 = GET_PTP(pe4);
    pe3 = GET_PE(pt3,virt,pml3_offset);
    if (!pe3 || !pe3->present) {
        printf("unmap: pe3 not present\n");
        return 0;
    }

    if (pe3->last) {
        *(uint64_t *)pe3 = 0;
        return PGSIZE_1G;
    }

    pt2 = GET_PTP(pe3);
    pe2 = GET_PE(pt2,virt,pml2_offset);
    if(!pe2->present) {
        printf("unmap: pe2 not present\n");
        return 0;
    }

    if (pe2->last) {
        *(uint64_t *)pe2 = 0;
        return PGSIZE_2M;
    }

    pt1 = GET_PTP(pe2);
    pe1 = GET_PE(pt1,virt,pml1_offset);
    if(!pe1 || !pe1->present) {
        printf("unmap: pe1 not present\n");
        return 0;
    }

    *(uint64_t *)pe1 = 0;

    return PGSIZE_4K;
}

bool _unmap_region(const struct task *const tsk, const void *virt, size_t len, pt_t *opt_pd,
        const char *file, const char *func, int line)
{
    //printf("unmap_region: %p[%lx] tsk=%p opt_pd=%p: %s:%s:%d\n",
      //    virt, len, (void *)tsk, (void *)opt_pd, file, func, line);

    pt_t *pd = opt_pd ? opt_pd : tsk->pd;
    const char *cur_virt = virt;
    const char *virt_end = ((const char *)virt) + len;
    size_t pg_size, ret;

    while (cur_virt < virt_end) {
        pg_size = get_pe_size(pd, cur_virt);
        ret = unmap(pd, cur_virt, pg_size);
        if (ret == 0 || ret != pg_size)
            return false;
        cur_virt += pg_size;
    }

    return true;
}

bool _map_region(const struct task *const tsk, const void *virt, const void *phys, size_t len, int flags, pt_t *opt_pd,
        const char *file, const char *func, int line)
{
    pt_t *const pd = (!opt_pd && tsk && tsk->pd) ? tsk->pd : opt_pd;
    /*
    printf("map_region: %p -> %p [%lx] tsk=%p, pd=%p %s:%s:%u\n",
            virt, phys, len, (void *)tsk, (void *)pd,
            file, func, line);
    */

    if ((void *)((uintptr_t)virt & ~(PGSIZE_4K-1)) != virt) {
        printf("map_region: misaligned virtual address: %p\n", virt);
        return false;
    }

    if ((void *)((uintptr_t)phys & ~(PGSIZE_4K-1)) != phys) {
        printf("map_region: misaligned physical address: %p\n", phys);
        return false;
    }


    if (pd == NULL) {
        printf("map_region: NULL pd\n");
        return false;
    }

    const char *virt_end = ((const char *)virt) + len;
    const char *cur_virt = virt;
    const char *cur_phys = phys;

    //printf("map_region: using pd=%p, virt_end=%p\n", (void *)pd, (void *)virt_end);

    while (cur_virt < virt_end)
    {
        //printf("map_region: %p && PGSIZE_2M == %lx, %p && PGSIZE_2M == %lx\n",
        //        cur_virt, (uintptr_t)cur_virt % PGSIZE_2M,
        //        cur_phys, (uintptr_t)cur_phys % PGSIZE_2M);
        if (    ((uintptr_t)cur_virt % PGSIZE_1G) == 0 &&
                ((uintptr_t)cur_phys % PGSIZE_1G) == 0 &&
                ((cur_virt + PGSIZE_1G) <= virt_end)) {
            //printf("map_region: attempting to map 1GiB %p->%p\n", cur_virt, cur_phys);
            if (!create_page_entry_1g(pd, cur_virt, cur_phys, flags, tsk ? tsk->pid : 0))
                return false;
            cur_virt += PGSIZE_1G;
            cur_phys += PGSIZE_1G;
        } else if (((uintptr_t)cur_virt % PGSIZE_2M) == 0 &&
                   ((uintptr_t)cur_phys % PGSIZE_2M) == 0 &&
                   ((cur_virt + PGSIZE_2M) <= virt_end)) {
            //printf("map_region: attempting to map 2MiB %p->%p\n", cur_virt, cur_phys);
            if (!create_page_entry_2m(pd, cur_virt, cur_phys, flags, tsk ? tsk->pid : 0))
                return false;
            cur_virt += PGSIZE_2M;
            cur_phys += PGSIZE_2M;
        } else {
            //printf("map_region: attempting to map 4KiB %p->%p\n", cur_virt, cur_phys);
            if (!create_page_entry_4k(pd, cur_virt, cur_phys, flags, tsk ? tsk->pid : 0))
                return false;
            cur_virt += PGSIZE_4K;
            cur_phys += PGSIZE_4K;
        }
    }
    //printf("map_region: done\n");
    return true;
}
