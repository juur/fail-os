#define _PAGE_C
#include "klibc.h"
#include "page.h"
#include "mem.h"
#include "cpu.h"
#include "frame.h"

volatile struct pt_t *kernel_pd;

void decode_flags(const pe_t *const pe)
{
	printf("%c%c%c%c%c%c",
			pe->present ? 'P' : '_',
			pe->user ? 'U' : 'S',
			pe->write ? 'W' : 'R',
			pe->cow ? 'C' : '_',
            pe->global ? 'G' : '_',
            pe->last ? 'L' : '_'
		  );
}


void print_mm(const pt_t *const pt4)
{
	uint64_t i,j,k,m;
	uint64_t addr;
	const pt_t *pt3,*pt2,*pt1;
	const pe_t *pe4,*pe3,*pe2,*pe1;

	printf("print_mm: pt4 @ %p\n", (void *)pt4);
	for(i=0;i<PT_SIZE;i++) /* PML4 */
	{
		pe4 = &GET_PE_N(pt4,i);
		pt3 = GET_PTP(pe4);
		if(pe4->present) {
			printf("pt4[%lx] = pt3 @ %p: ", i, (void *)pt3);
			decode_flags(pe4);

			for(j=0;j<PT_SIZE;j++) /* PML3 */
			{
				pe3 = &GET_PE_N(pt3, j);
				pt2 = GET_PTP(pe3);
				if(pe3->present && pe3->last) {
					addr = (uint64_t)GET_PTP(pe3);
					printf("\n pt3[%lx]: %lx => %lx 1G: ",
							j, GET_VIRT(i,j,0,0), addr);
					decode_flags(pe3);
				} else if(pe3->present) {
					printf("\n pt3[%lx] = pt2 @ %p: ", j, (void *)pt2);
					decode_flags(pe3);

					for(k=0;k<PT_SIZE;k++) /* PML2 */
					{
						pe2 = &GET_PE_N(pt2, k);
						pt1 = GET_PTP(pe2);
						if(pe2->present && pe2->last) {
							printf("\n  pt2[%lx]: %lx => %p: 2M: ",
									k, GET_VIRT(i,j,k,0), (void *)pt1);
							decode_flags(pe2);
						} else if(pe2->present) {
							printf("\n  pt2[%lx] = pt1 @ %p: ", k, (void *)pt1);
							decode_flags(pe2);

							for(m=0;m<PT_SIZE;m++) /* PML1 */
							{
								pe1 = &GET_PE_N(pt1, m);
								addr = (uint64_t)GET_PTP(pe1);
								if(!pe1->present) continue;
								printf("\n   pt1[%lx]: %lx => %lx: 4k: ", 
										m, GET_VIRT(i,j,k,m), addr);
								decode_flags(pe1);
							} /* PML1 */
						}
					} /* PML2 */

				}
			} /* PML3 */
		}
	} /* PML4 */
	printf("\n");
}

void free_mm(pt_t *const pt4)
{
	uint64_t i,k,j;//,m;
	pt_t *pt3,*pt2,*pt1;
	pe_t *pe4,*pe3,*pe2;//,*pe1;

	for(i=0;i<PT_SIZE;i++) /* PML4 */
	{
		pe4 = &GET_PE_N(pt4,i);
		pt3 = GET_PTP(pe4);
		if(pe4->present) {
			for(j=0;j<PT_SIZE;j++) /* PML3 */
			{
				pe3 = &GET_PE_N(pt3, j);
				pt2 = GET_PTP(pe3);
				if(pe3->present && pe3->last) {
					pe3->present = 0;
				} else if(pe3->present) {
					for(k=0;k<PT_SIZE;k++) /* PML2 */
					{
						pe2 = &GET_PE_N(pt2, k);
						pt1 = GET_PTP(pe2);
						if(pe2->present && !pe2->last)
							kfree(pt1);
						pe2->present = 0;
					}
					kfree(pt2);
					pe3->present = 0;
				}
			}
			kfree(pt3);
			pe4->present = 0;
		}
	}
	kfree(pt4);
}

void clone_mm(pt_t *const old_pt4, pt_t *const new_pt4, void *const owner, const bool cow_existing)
{
	int i,j,k,m;

	// printf("clone_mm: %x -> %x\n", old_pt4, new_pt4);

	pt_t *new_pt3, *new_pt2, *new_pt1;
	pe_t *new_pe4, *new_pe3, *new_pe2, *new_pe1;
	pt_t *old_pt3, *old_pt2, *old_pt1;
	pe_t *old_pe4, *old_pe3, *old_pe2, *old_pe1;

	*new_pt4 = *old_pt4;
	//memcpy(new_pt4, old_pt4, sizeof(pt_t));

	for(i=0;i<PT_SIZE;i++) /* clone PML4 */
	{
		old_pe4 = &GET_PE_N(old_pt4, i);
		new_pe4 = &GET_PE_N(new_pt4, i);

		if(old_pe4->present)
		{
			new_pt3 = (pt_t *)kmalloc_align(sizeof(pt_t),"clone_mm.pe4", owner, KMF_ZERO);
			if(!new_pt3) goto fail_pt3;
			old_pt3 = GET_PTP(old_pe4);
			*new_pt3 = *old_pt3;
			SET_PTP(new_pe4, (uint64_t)new_pt3);

			for(j=0;j<PT_SIZE;j++) /* clone PML3 */
			{
				old_pe3 = &GET_PE_N(old_pt3, j);
				new_pe3 = &GET_PE_N(new_pt3, j);

				if(old_pe3->present && old_pe3->user && old_pe3->last) {	/* 1G pte */
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
					new_pt2 = (pt_t *)kmalloc_align(sizeof(pt_t),"clone_mm.pe3", owner, KMF_ZERO);
					if(!new_pt2) goto fail_pt2;

					old_pt2 = GET_PTP(old_pe3);
					*new_pt2 = *old_pt2;
					SET_PTP(new_pe3, (uint64_t)new_pt2);

					for(k=0;k<PT_SIZE;k++) /* clone PML2 */
					{
						old_pe2 = &GET_PE_N(old_pt2, k);
						new_pe2 = &GET_PE_N(new_pt2, k);

						if(old_pe2->present && old_pe2->user && old_pe2->last) { /* 2M pte */
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
							new_pt1 = (pt_t *)kmalloc_align(sizeof(pt_t),"clone_mm.pe2", owner, KMF_ZERO);
							if(!new_pt1) goto fail_pt1;
							old_pt1 = GET_PTP(old_pe2);
							*new_pt1 = *old_pt1;
							SET_PTP(new_pe2, (uint64_t)new_pt1);

							for(m=0;m<PT_SIZE;m++) /* clone PML1 */
							{
								old_pe1 = &GET_PE_N(old_pt1, m);
								new_pe1 = &GET_PE_N(new_pt1, m);

								if(old_pe1->present && old_pe1->user) {
									new_pe1->write = 0;
									new_pe1->cow = 1;
									new_pe1->global = 0;
									new_pe1->user = 1;
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

	return;

fail_pt1:
fail_pt2:
fail_pt3:
	printf("clone_mm: failed to allocate memory\n");
	return;
}

bool create_page_entry_1g(pt_t *const pt4, const uint64_t _virt, 
		const uint64_t _phys, const int flag, struct task *const owner)
{
	v_addr virt;
	pe_t *pe4, *pe3;
	pt_t *pt3;

	virt.addr = _virt;
	pe4 = &GET_PE(pt4,virt,pml4_offset);

	if(!pe4->present) {
		uint64_t tmp = (uint64_t)kmalloc_align(sizeof(pt_t),"pg_ent_1g.pe4", owner, KMF_ZERO);
		if(!tmp) goto pg_fail;
		SET_PTP(pe4, tmp);
		pe4->present = 1;
		pt3 = (pt_t *)tmp;
		if(flag & PEF_U) pe4->user = 1;
		if(flag & PEF_W) pe4->write = 1;
	} else {
		pt3 = GET_PTP(pe4);
	}

	pe3 = &GET_PE(pt3,virt,pml3_offset);
	if(pe3->present) {
		printf("create_page_entry_1g: pe3 already present virt=%lx phys=%lx\n", _virt, _phys);
		print_mm(pt4);
		while(1) hlt();
		// either change or barf?
	}

	SET_PHYS_K(pe3,_phys);
	if(flag & PEF_P) pe3->present = 1;
	if(flag & PEF_U) pe3->user = 1;
	if(flag & PEF_W) pe3->write = 1;
	pe3->last = 1;
	if(flag & PEF_G) pe3->global = 1;
	
	return true;
pg_fail:
	printf("create_page_entry_1g: failed\n");
	return false;
}

bool create_page_entry_2m(pt_t *const pt4, const uint64_t _virt, 
		const uint64_t _phys, const int flag, struct task *const owner)
{
	v_addr virt;
	pe_t *pe4, *pe3, *pe2;
	pt_t *pt3, *pt2;

	virt.addr = _virt;
	pe4 = &GET_PE(pt4,virt,pml4_offset);

	if(!pe4->present) {
		uint64_t tmp = (uint64_t)kmalloc_align(sizeof(pt_t),"pg_ent_2m.pe4", owner, KMF_ZERO);
		if(!tmp) goto pg_fail;
		SET_PTP(pe4, tmp);
		pe4->present = 1;
		pt3 = (pt_t *)tmp;
		if(flag & PEF_U) pe4->user = 1;
		if(flag & PEF_W) pe4->write = 1;
	} else {
		pt3 = GET_PTP(pe4);
	}

	pe3 = &GET_PE(pt3,virt,pml3_offset);

	if(!pe3->present) {
		uint64_t tmp = (uint64_t)kmalloc_align(sizeof(pt_t),"pg_ent_2m.pe3", owner, KMF_ZERO);
		if(!tmp) goto pg_fail;
		SET_PTP(pe3, tmp);
		pe3->present = 1;
		pt2 = (pt_t *)tmp;
		if(flag & PEF_U) pe3->user = 1;
		if(flag & PEF_W) pe3->write = 1;
	} else {
		pt2 = GET_PTP(pe3);
	}

	pe2 = &GET_PE(pt2,virt,pml2_offset);
	if(pe2->present) {
		printf("create_page_entry_2m: pe2 already present\n");
		while(1) hlt();
	}

	SET_PHYS_K(pe2,_phys);
	if(flag & PEF_P) pe2->present = 1;
	if(flag & PEF_U) pe2->user = 1;   
	if(flag & PEF_W) pe2->write = 1; 
	pe2->last = 1;
	if(flag & PEF_G) pe2->global = 1; 

	return true;

pg_fail:
	printf("create_page_entry_2m: failed\n");
	return false;
}

bool create_page_entry_4k(pt_t *const pt4, const uint64_t _virt, 
		const uint64_t _phys, const int flag, struct task *const owner)
{
	v_addr virt;
	pe_t *pe4, *pe3, *pe2, *pe1;
	pt_t *pt3, *pt2, *pt1;

	//printf("create_4k: %lx -> %lx\n", _virt, _phys);

	virt.addr = _virt & ~0xfff;
	pe4 = &GET_PE(pt4,virt,pml4_offset);

	if(!pe4->present) {
		uint64_t tmp = (uint64_t)kmalloc_align(sizeof(pt_t),"pg_ent_4k.pe4", owner, KMF_ZERO);
		if(!tmp) goto pg_fail;
		SET_PTP(pe4, tmp);
		pe4->present = 1;
		pt3 = (pt_t *)tmp;
	} else {
		pt3 = GET_PTP(pe4);
	}
	if(flag & PEF_U) pe4->user = 1;
	if(flag & PEF_W) pe4->write = 1;

	pe3 = &GET_PE(pt3,virt,pml3_offset);

	if(!pe3->present) {
		uint64_t tmp = (uint64_t)kmalloc_align(sizeof(pt_t),"pg_ent_4k.pe3", owner, KMF_ZERO);
		if(!tmp) goto pg_fail;
		SET_PTP(pe3, tmp);
		pe3->present = 1;
		pt2 = (pt_t *)tmp;
	} else {
		pt2 = GET_PTP(pe3);
	}
	if(flag & PEF_U) pe3->user = 1;
	if(flag & PEF_W) pe3->write = 1;

	pe2 = &GET_PE(pt2,virt,pml2_offset);

	if(!pe2->present) {
		uint64_t tmp = (uint64_t)kmalloc_align(sizeof(pt_t),"pg_ent_4k.pe2", owner, KMF_ZERO);
		if(!tmp) goto pg_fail;
		SET_PTP(pe2, tmp);
		pe2->present = 1;
		pt1 = (pt_t *)tmp;
	} else {
		pt1 = GET_PTP(pe2);
	}
	if(flag & PEF_U) pe2->user = 1;
	if(flag & PEF_W) pe2->write = 1;

	pe1 = &GET_PE(pt1,virt,pml1_offset);
	if(pe1->present) {
		printf("create_page_entry_4k: pe1 already present\n");
		while(1) hlt();
	}

	SET_PHYS_K(pe1,_phys);
	if(flag & PEF_P) pe1->present = 1;
	if(flag & PEF_U) pe1->user = 1;   
	if(flag & PEF_W) pe1->write = 1; 
	// pe1->last = 1; // bit7 is PAT
	if(flag & PEF_G) pe1->global = 1; 

	return true;
pg_fail:
	printf("create_page_entry_4k: failed\n");
	return false;
}

pe_t *get_pe(pt_t *const pd, const uint64_t _virt)
{
	v_addr virt;
	pe_t *pe4,*pe3,*pe2,*pe1;
	pt_t *pt4,*pt3,*pt2,*pt1;

	pt4 = pd;
	virt.addr = _virt;

	pe4 = &GET_PE(pt4,virt,pml4_offset);
	if(!pe4->present) return NULL;

	pt3 = GET_PTP(pe4);
	pe3 = &GET_PE(pt3,virt,pml3_offset);
	if(!pe3->present) return NULL;
	if(pe3->last) return pe3;

	pt2 = GET_PTP(pe3);
	pe2 = &GET_PE(pt2,virt,pml2_offset);
	if(!pe2->present) return NULL;
	if(pe2->last) return pe2;

	pt1 = GET_PTP(pe2);
	pe1 = &GET_PE(pt1,virt,pml1_offset);
	if(!pe1->present) return NULL;
	return pe1;
}

uint64_t get_pe_size(const pt_t *const pd, const uint64_t _virt)
{
	v_addr virt;
	const pe_t *pe4,*pe3,*pe2,*pe1;
	const pt_t *pt4,*pt3,*pt2,*pt1;

	pt4 = pd;
	virt.addr = _virt;

	pe4 = &GET_PE(pt4,virt,pml4_offset);
	if(!pe4->present) return 0;

	pt3 = GET_PTP(pe4);
	pe3 = &GET_PE(pt3,virt,pml3_offset);
	if(!pe3->present) return 0;
	if(pe3->last) return PGSIZE_1G;

	pt2 = GET_PTP(pe3);
	pe2 = &GET_PE(pt2,virt,pml2_offset);
	if(!pe2->present) return 0;
	if(pe2->last) return PGSIZE_2M;

	pt1 = GET_PTP(pe2);
	pe1 = &GET_PE(pt1,virt,pml1_offset);
	if(!pe1->present) return 0;

	return PGSIZE_4K;
}

uint64_t get_phys_address(const pt_t *const pd, const uint64_t _virt)
{
	unsigned long ret = 0;
	v_addr virt;
	const pe_t *pe4,*pe3,*pe2,*pe1;
	const pt_t *pt4,*pt3,*pt2,*pt1;

	pt4 = pd;
	virt.addr = _virt;

	pe4 = &GET_PE(pt4,virt,pml4_offset);
	if(!pe4->present) return -1UL;

	pt3 = GET_PTP(pe4);
	pe3 = &GET_PE(pt3,virt,pml3_offset);

	if(!pe3->present) return -1UL;


	if(pe3->last) {
		// 1G entry
		ret = GET_PHYS(pe3,g,virt);
		goto end;
	}

	pt2 = GET_PTP(pe3);
	pe2 = &GET_PE(pt2,virt,pml2_offset);
	if(!pe2->present) return -1UL;

	if(pe2->last) {
		// 2M entry
		ret = GET_PHYS(pe2,m,virt);
		goto end;
	}

	// 4k entry
	pt1 = GET_PTP(pe2);
	pe1 = &GET_PE(pt1,virt,pml1_offset);
	if(!pe1->present) return -1UL;

	ret = GET_PHYS_K(pe1,virt);
end:
	return ret;
}

void set_pe_in_pt(pt_t *pt, uint64_t virt, uint64_t phys, int present, int write, int user, int is_frame)
{
	// how to find out what PML1,2,3,4 we are for bitmasking?
	// call set_pe
}

void set_pe(pe_t *pe, uint64_t virt, uint64_t phys, unsigned present, 
		unsigned write, unsigned user, unsigned is_frame)
{
	*((uint64_t *)pe) = 0;
	pe->global = is_frame;
	pe->write = write;
	pe->user = user;
	pe->present = present;
	pe->base = (phys&~0xfff)>>12;
}

int grow_page(struct task *const ctsk, void *const addr, pt_t *const pt)
{
	if( (addr > ctsk->heap_end || addr < ctsk->heap_start) 
			&& (addr > ctsk->stack_end || addr < ctsk->stack_start) ) {
		printf("grow_page: %p is outside %p:%p and %p:%p\n", 
				(void *)addr, 
				(void *)ctsk->heap_start, (void *)ctsk->heap_end,
				(void *)ctsk->stack_start, (void *)ctsk->stack_end
				);
		return -2;
	}
	if(!create_page_entry_4k(pt, ((uint64_t)addr & ~0xfff), (uint64_t)find_frame(ctsk),
			PEF_P|PEF_U|PEF_W, ctsk))
		return -3;
	__asm__ volatile("invlpg %0"::"m"(addr));
	return 0;
}

