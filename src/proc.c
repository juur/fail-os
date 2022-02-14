#define _PROC_C
#include "proc.h"
#include "klibc.h"
#include "mem.h"
#include "page.h"
#include "frame.h"
#include "cpu.h"
#include "elf64.h"
#include "file.h"
#include "syscall.h"

uint64_t	curtask = 0;
unsigned long firsttask = 1;
unsigned long nosched;
struct task tasks[NUM_TASKS] __attribute__((aligned (16)));
static int task_lock = 0;

extern pt_t *kernel_pd;

const char *const state_names[STATE_NUM] = {
	"STATE_EMPTY",
	"STATE_KILLING",
	"STATE_CREATING",
	"STATE_RUNNING",
	"STATE_WAIT",
	"STATE_EXECVE",
	"STATE_FORK"
};

static void dump_task(const struct task *t);

/* FIXME: needs to lock and find another slot for ctsk */

void lock_tasks(void)
{
	spin_lock(&task_lock);
	nosched = 1;
}

void unlock_tasks(void)
{
	spin_unlock(&task_lock);
	nosched = 0;
}

static inline void switch_to(const struct task *const restrict new_tsk, volatile struct regs *const restrict r)
{
	*r = new_tsk->tss;
	/* xsave area is restored on exit from idt_main */
	global_tss.rsp0 = (uint64_t)new_tsk->kernelsptr;
	
	write_msr(MSR_KERNEL_GSBASE, (uint64_t)new_tsk->kerngsbase);
	write_msr(MSR_GSBASE,        (uint64_t)new_tsk->gsbase);
	write_msr(MSR_FSBASE,        (uint64_t)new_tsk->tls);

	/*
	printf("switch_to[%ld]:  DPL=%x gsbase:%lx kerngsbase:%lx\n",
			new_tsk->pid,
			(uint8_t)(new_tsk->tss.cs & 0x3),
			new_tsk->gsbase, 
			new_tsk->kerngsbase);
			*/

	set_cr3(new_tsk->pd);
}

static inline void save_state(struct task *const restrict old, const volatile struct regs *const restrict r)
{
	old->tss = *r;

	old->kerngsbase = (void *)read_msr(MSR_KERNEL_GSBASE);
	old->gsbase     = (void *)read_msr(MSR_GSBASE);
	old->tls        = (void *)read_msr(MSR_FSBASE);

	/*
	printf("save_state[%ld]: CPL=%x gsbase:%lx kerngsbase:%lx\n", 
			old->pid,
			(uint8_t)(old->tss.cs & 0x3),
			old->gsbase, 
			old->kerngsbase);
			*/
	/* xsave area is saved on entry to idt_main */
}

bool force_sched = false;

void sched_main(volatile struct regs *const r)
{
	struct task *t;
	unsigned long i;
	unsigned long new_tsk;
	bool running;

	force_sched = false;


	lock_tasks(); {
		for(i = 1; i<NUM_TASKS; i++) {
			if( i == curtask ) 
				continue;	// don't touch the current task
			t = get_task(i);

			if(t) switch(t->state) 
			{
				case STATE_KILLING:
					if(!t->tss.rip) 
						break;
					t->tss.rip = 0;
					printf("sched_main: killing task %lx during task %lx\n", i, curtask);
					// FIXME if(t->pd) { free_pd(t->pd); t->pd = NULL; }
					t->state = STATE_EMPTY;
					cli(); _brk();
					while(1) hlt();
					break;
			}
		}

		i = curtask + 1;
		running = true;

		while(running)
		{
			if( i >= NUM_TASKS ) {
				i = 1;
			} else if( i == curtask ) {
				if ( curtask == 0 )
					goto unlock;
				i = 0;
				running = false;
			} else if( tasks[i].state == STATE_RUNNING 
					|| tasks[i].state == STATE_EXECVE 
					|| tasks[i].state == STATE_FORK ) {
				running = false;
			} else {
				i++;
			}
		}

		/* task to switch to */
		new_tsk = i;

		if((t = get_task(curtask)) == NULL)
			goto unlock;
		/* curtask and t are the old task */

		/* save the context (struct regs) into the current task.tss */
		save_state(t, r);
		//printf("switching from: pid:%lx rip:%0x[%0x]/%0x rsp:%0x[%0x] pd:%p ds:%x cs:%x ss:%x %s\n", curtask, r->rip, get_phys_address(t->pd, r->rip), t->syscall_rip, r->rsp, get_phys_address(t->pd, r->rsp), (void *)t->pd, r->ds, r->cs, r->ss, state_names[t->state]);

		curtask = new_tsk;
		if((t = get_task(curtask)) == NULL)
			goto unlock;
		/* curtask and t are now the new task */

		switch_to(t, r);
		//printf("switching to:   pid:%lx rip:%0x[%0x]/%0x rsp:%0x[%0x] pd:%p ds:%x cs:%x ss:%x %s\n", curtask, r->rip, get_phys_address(t->pd, r->rip), t->syscall_rip, r->rsp, get_phys_address(t->pd, r->rsp), (void *)t->pd, r->ds, r->cs, r->ss, state_names[t->state]);
	}

unlock:
	unlock_tasks();
}

/*
void sched_fail(void)
{
	printf("sched_fail()");
	while(true) 
		hlt();
}
*/

void print_tasks(void)
{
	unsigned long pid;
	const struct task *t;

	// FIXME
	printf(" curtask:%lx\n", curtask);

	for(pid=0;pid<NUM_TASKS;pid++) {
		if ((t = get_task(pid)) == NULL)
			continue;
		//if (t->state == STATE_EMPTY)
		//	continue;
		print_task(t);
	}
}


void print_task(const struct task *const restrict tsk)
{
	const struct regs *restrict t = &tsk->tss;

	printf("  task:%c%p[%s] n:%s rip:%lx rsp:%lx "
			"rax:%lx rbp:%lx rflags:%lx "
			"pd:%p cs:%lx ss:%lx gs:%lx "
			"sys_rip:%lx sys_esp:%lx"
			"\n",
			tsk == &tasks[curtask] ? '*' : ' ',
			(void *)tsk, state_names[tsk->state],
			&tsk->name[0],
			t->rip, t->rsp,
			t->rax, t->rbp, t->rflags,
			(void *)tsk->pd, t->cs, t->ss, t->gs,
			tsk->syscall_rip, (uint64_t)tsk->stacksave);
}


uint64_t find_free_task(const bool lock)
{
	if(lock) 
		lock_tasks();

	for(uint64_t i=1; i<NUM_TASKS; i++) // we don't use PID==0 !
	{
		if(tasks[i].state == STATE_EMPTY) { 
			tasks[i].state = STATE_CREATING;
			if(lock) 
				unlock_tasks(); 
			return i; 
		}
	}

	if(lock) 
		unlock_tasks();
	return -1UL;
}


#if 0
void *add_page_task(struct task *const tsk)
{
	//	unsigned long end = tsk->mem_end;
	void *new_frame = find_frame(tsk);
	//struct page_table *pt;

	if(!new_frame) goto fail;

	// FIXME
	/*
	   if(!has_pte(tsk->pd, end)) {
	   pt = kmalloc_align(sizeof(pt_t),"add_page_task.pt");
	   if(!pt) goto fail_frame;
	   set_pde_4k(tsk->pd, pt, tsk->mem_end, 1, 1, 1);
	   }

	   set_pte_pde_4k(tsk->pd, end, new_frame, 1, 1, 1, 0);
	   tsk->mem_end += 0x1000;
	   */

	return new_frame;

	//fail_frame:
	//clear_frame(new_frame);
fail:
	return 0;
}
#endif

void setup_task(struct task *const tsk, const uint64_t rip, const int type, 
		const pt_t *const pd, const char *const name, const uint64_t rsp, 
		const int pid)
{
	struct regs *const t = &tsk->tss;

	//printf("setup_task: tsk:%p rip:%lx type:%x pd:%p name:%s rsp:%lx\n", (void *)tsk, rip, type, (void *)pd, name, rsp);

	tsk->state     = STATE_CREATING;
	tsk->this_task = tsk;
	tsk->pd        = (pt_t *)pd;
	tsk->pid       = pid;

	tsk->syscall_rip	= 0x0;
	tsk->syscall_rflags	= 0x0;
	tsk->stacksave		= 0x0;

	memset(&tsk->tss, 0, sizeof(tsk->tss));
	if( name )
		strncpy(tsk->name, name, sizeof(tsk->name)-1);

	t->rip		= rip;
	t->rflags	= 0x201;
	t->rsp		= rsp;

	switch(type)
	{
		case KERNEL_TASK:
			t->cs = _KERNEL_CS|CPL_0;
			t->ss = _KERNEL_DS|CPL_0;
			t->ds = t->es = t->gs = 0;//_KERNEL_DS;

			tsk->kernelstack = kmalloc_align(STACK_SIZE, "krnlstack", tsk, KMF_ZERO);
			tsk->kernelsptr  = (void *)((uint64_t)tsk->kernelstack + STACK_SIZE - 8);
			tsk->gsbase      = tsk;
			tsk->kerngsbase  = 0x0;
			break;
		case CLONE_TASK:
		default:
			//printf("setup_task: CLONE_TASK: rip=%lx rsp=%lx\n", t->rip, t->rsp);
			t->cs = (_USER_CS|CPL_3);
			t->ss = (_USER_DS|CPL_3);
			t->ds = t->es = t->gs = 0;//(_USER_DS|CPL_3);

			tsk->gsbase      = 0x0;
			tsk->kerngsbase  = tsk;
			tsk->kernelstack = kmalloc_align(STACK_SIZE, "krnlstack", tsk, KMF_ZERO);
			tsk->kernelsptr  = (void *)((uint64_t)tsk->kernelstack + STACK_SIZE - 8);

			break;
	}


	if(type != CLONE_TASK) tsk->state = STATE_RUNNING;
}

long do_exec(struct task *const t, const char *const f, uint8_t **const code, 
		uint64_t *const clen, uint8_t **const data, uint64_t *const dlen, 
		uint64_t *const vaddr, uint64_t *const daddr)
{
	elf64_hdr hdr;
	unsigned char buf[64];
	int shnum, phnum;
	uint64_t offset;

	elf64_phdr *phdr = NULL;
	elf64_shdr *shdr = NULL;
	struct fileh *fh = NULL;
	uint8_t *tmp     = NULL;
	struct elf *elf  = NULL;

	//printf("do_exec: task=%p, f=%s, code=%p, clen=%p\n", (void *)t, f, (void *)code, (void *)clen);

	fh = do_open(f, NULL, 0, 0, NULL); // FIXME flags FIXME NULL means kernel

	*code = *data = 0;
	*vaddr = *daddr = *clen = *dlen = 0;

	if(!fh) {
		printf("do_exec: can't open file: %s\n", f);
		return -1;
	}

	if(do_read(fh, (int8_t *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		printf("do_exec: didn't read something\n");
		goto fail;
	}

	memset(buf, 0,           sizeof(buf));
	memcpy(buf, &hdr.ei_mag, sizeof(hdr.ei_mag));

	if(buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
		printf("do_exec: not an ELF: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
		goto fail;
	}

	/* printf("do_exec: ver:%x - %s / %s / %s[%x]: machine:%x\n", hdr.ei_version, ELFclass[hdr.ei_class], ELFdata[hdr.ei_data], ELFosabi[hdr.ei_osabi], hdr.ei_abiversion, hdr.e_machine); */
	if(	hdr.ei_class != ELFCLASS64 
			|| hdr.ei_data != ELFDATA2LSB 
			|| !(hdr.ei_class != ELFOSABI_SYSV 
				&& hdr.ei_class != ELFOSABI_LINUX) 
			|| hdr.e_machine != EM_X86_64 ) {
		printf("Unsupported ELF ABI, machine type, class or data\n");
		goto fail;
	}

	/* printf("do_exec: %s, version: %x\n", ELFetype[hdr.e_type], hdr.e_version); */

	if(hdr.e_type != ET_EXEC) {
		printf("do_exec: unsupported e_type\n");
		goto fail;
	}

	//printf("do_exec: phnum = %x shnum = %x\n", hdr.e_phnum, hdr.e_shnum);

	if((elf = kmalloc(sizeof(struct elf), "elf", t, KMF_ZERO)) == NULL)
        goto fail;


	if((elf->sh = kmalloc(sizeof(struct elf_section) * hdr.e_shnum, "elf_sh", t, KMF_ZERO)) == NULL)
        goto fail;

	if((elf->ph = kmalloc(sizeof(struct elf_segment) * hdr.e_phnum, "elf_ph", t, KMF_ZERO)) == NULL)
        goto fail;

	memcpy(&elf->h, &hdr, sizeof(elf->h));

	//printf("do_exec: entry: %lx, phoff: %lx, shoff: %lx\n", hdr.e_entry, hdr.e_phoff, hdr.e_shoff);

	offset = hdr.e_phoff;

	for(phnum = 0; phnum < hdr.e_phnum; phnum++ )
	{
		do_lseek(fh, offset, SEEK_SET);
		do_read(fh, (int8_t *)&elf->ph[phnum].hdr, sizeof(elf64_phdr));
		offset += sizeof(elf64_phdr);
	}

	offset = hdr.e_shoff + hdr.e_shentsize;

	//printf("do_exec: elf:%p elf.sh:%p elf.ph:%p\n", (void *)elf, (void *)elf->sh, (void *)elf->ph);

	for(shnum = 0; shnum < hdr.e_shnum; shnum++)
	{
		do_lseek(fh, offset, SEEK_SET);
		do_read(fh, (int8_t *)&elf->sh[shnum].hdr, sizeof(elf64_shdr));
		offset += sizeof(elf64_shdr);
	}

	uint64_t lowaddr = -1, highaddr = 0;

	for(phnum = 0 ; phnum < hdr.e_phnum ; phnum++ )
	{
		phdr = &elf->ph[phnum].hdr;

		if(phdr->p_type >= PT_MAX) continue;
		//printf("do_exec: phdr[%x] %s (", phnum, phdr->p_type < PT_MAX ? ELFptype[phdr->p_type] : "#ERR"); print_bits(phdr->p_flags, bits_ELF_PF, 8, 0); printf(") p_offset %lx, sz: %lx/%lx, p_vaddr: %lx, p_paddr: %lx\n", phdr->p_offset, phdr->p_filesz, phdr->p_memsz, phdr->p_vaddr, phdr->p_paddr);
		if(phdr->p_type != PT_LOAD) continue;

		if(phdr->p_vaddr < lowaddr) {
			lowaddr = phdr->p_vaddr;
			if(highaddr == 0) highaddr = lowaddr;
		} else if(phdr->p_vaddr > highaddr) {
			highaddr = phdr->p_vaddr;
		}

		//		if( (phdr->p_flags & PF_X) && *code == 0) *code = phdr->p_vaddr;
		//		else if( (phdr->p_flags & PF_R) && *data == 0) *data = phdr->p_vaddr;

		highaddr += phdr->p_memsz;

		elf->ph[phnum].flags |= ES_LOADME;
	}

	highaddr += PAGE_SIZE - 1;
	highaddr &= ~0xfff;


    /* TODO record number & free somewhere? */
	tmp = (uint8_t *)find_n_frames((elf->frames = ((highaddr - lowaddr)/PAGE_SIZE)), t);
	memset(tmp, 0, highaddr - lowaddr);

	elf->lowaddr = lowaddr;
	elf->highaddr = highaddr;
	elf->page_start = tmp;

	//printf("do_exec lowaddr=%lx highaddr=%lx pages=%lx\n", lowaddr, highaddr, elf->frames);

	for(offset = lowaddr ; offset < highaddr ; offset += PAGE_SIZE, tmp += PAGE_SIZE) {
        //printf("do_exec: create_page_entry_4k: %p %lx %lx, P|U|W, %p\n",
        //        (void *)t->pd,
        //        offset,
        //        (uint64_t)tmp,
        //        (void *)t);
		if(!create_page_entry_4k(t->pd, offset, (uint64_t)tmp, PEF_P|PEF_U|PEF_W, t))
            printf("do_exec: unable to map executable data\n");
    }


    //printf("do_exec: created page entries\n");

	for(phnum = 0; phnum < hdr.e_phnum ; phnum++ )
	{
		if( !(elf->ph[phnum].flags & ES_LOADME) 
				|| (elf->ph[phnum].flags & ES_LOADED)) continue;

		phdr = &elf->ph[phnum].hdr;

		if((phdr->p_flags & (PF_X|PF_R)) == (PF_X|PF_R)) {
			if(!*code) {
				*code = (uint8_t *)get_phys_address(t->pd, phdr->p_vaddr);
				*clen = phdr->p_memsz;
				*vaddr = phdr->p_vaddr;
			}

			do_lseek(fh, phdr->p_offset, SEEK_SET);
			do_read(fh, (int8_t *)get_phys_address(t->pd, phdr->p_vaddr), 
					phdr->p_filesz);
		} else if ((phdr->p_flags & PF_R) == PF_R) {
			if(!*data) {
				*data = (uint8_t *)get_phys_address(t->pd, phdr->p_vaddr);
				*dlen = phdr->p_memsz;
				*daddr = phdr->p_vaddr;
			}

			do_lseek(fh, phdr->p_offset, SEEK_SET);
			do_read(fh, (int8_t *)get_phys_address(t->pd, phdr->p_vaddr), 
					phdr->p_filesz);
		} else {
		}
	}

    //printf("do_exec: done phnum\n");

	for(shnum = 0 ; shnum < hdr.e_shnum ; shnum++)
	{
		shdr = &elf->sh[shnum].hdr;

		if(shdr->sh_type == SHT_NULL) continue;
		//printf("do_exec: shdr[%x:%p] %s (", shnum, (void *)shdr, ELFshtype[shdr->sh_type]); print_bits(shdr->sh_flags, bits_SHF, 8, 0); printf(") sh_addr: %lx, sh_offset: %lx, sh_size: %lx\n", shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
		if(shdr->sh_type != SHT_PROGBITS ||
				(shdr->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) != 
				(SHF_ALLOC|SHF_EXECINSTR)) {
			continue;
		} else if (*vaddr) {
			//printf("do_exec: double shdr\n");
			continue;
		} else {
			//	*vaddr = shdr->sh_addr;
			continue;
		}
	}
    //printf("do_exec: done shnum\n");

	*vaddr = elf->h.e_entry;

	do_close(fh, t);
	t->elf = elf;
	return 0;

fail:
	if(elf) {
		if(elf->ph)
			kfree(elf->ph);
		if(elf->sh)
			kfree(elf->sh);
		kfree(elf);
	}

	if(fh)
		do_close(fh, t);
	return -1;
}

struct task *get_task(const uint64_t i)
{
	if(i > NUM_TASKS) goto fail;

	switch(tasks[i].state)
	{
		case STATE_EMPTY:
			goto fail;
			break;
		default:
			return &tasks[i];
			break;
	}

fail:
	return NULL;
}

__attribute__((nonnull)) static uint64_t do_fork(const struct task *const ctask, const struct regs *const cr, 
		const uint64_t rip, const uint64_t rsp, const uint64_t rflags)
{
	uint64_t me = curtask;
	uint64_t newpid;
	struct task *ntask;
	pt_t *newpd;

	/*
	printf("do_fork[%lx]: rip=%lx/%lx/%lx, rsp=%lx/%lx/%p, rflags=%lx/%lx/%lx\n", 
			me,
			rip, ctask->tss.rip, ctask->syscall_rip,
			rsp, ctask->tss.rsp, (void *)ctask->stacksave,
			rflags, ctask->tss.rflags, ctask->syscall_rflags
		  );
		  */

	newpid = find_free_task(false);

	if(newpid == -1UL) {
		printf("do_fork[%lx]: no pids\n", me);
		goto fail;
	}

	ntask = get_task(newpid);

	/* the new task needs to return from the next sched as if returning
	 * from sys_fork. the current task is in kernel mode we can't have the
	 * new task also in kernel mode as they share the same kernel stack
	 * page frames
	 */

	/* create a new page table */
	newpd = (pt_t *)kmalloc_align(sizeof(pt_t), "fork.pml4", ntask, KMF_ZERO);
	if(!newpd) {
		printf("do_fork[%lx]: cannot kmalloc_align pml4\n", me);
		ntask->state = STATE_EMPTY;
		newpid = -1UL;
		goto fail;
	}

	/* clone the page table (sets up COW) */
	clone_mm(ctask->pd, newpd, ntask, true);
	/* invalidate the tlb as we have changed the current tasks
	 * page table, making entries cow */
	set_cr3(ctask->pd);
	
	/* setup task will set our cs/ss to user, give us a new kernel stack */
	setup_task(ntask, rip, CLONE_TASK, newpd, (char *)&ctask->name, rsp, newpid);

	/* copy the context */
	ntask->tss = *cr;
	//memcpy(&ntask->tss, cr, sizeof(struct regs));

	/* fix-up the kernel stuff */
	ntask->tss.cs = (_USER_CS|CPL_3);
	ntask->tss.ss = (_USER_DS|CPL_3);
	ntask->tss.ds = ntask->tss.es = ntask->tss.gs = 0x0;
	ntask->kerngsbase = ntask;
	ntask->gsbase     = 0x0;

	/* setup_task will copy from parent, rax is the sys_fork return code for the child */
	ntask->tss.rax = 0x0;

	/* these three were saved in sysenter from user mode prior to sys_fork */
	ntask->tss.rflags = rflags;
	ntask->tss.rip    = rip;
	ntask->tss.rsp    = rsp;

	ntask->syscall_rflags = 0x0;
	ntask->syscall_rip    = 0x0;
	ntask->stacksave      = 0x0;

	ntask->code_start  = ctask->code_start;
	ntask->code_end    = ctask->code_end;
	ntask->data_start  = ctask->data_start;
	ntask->data_end    = ctask->data_end;
	ntask->stack_start = ctask->stack_start;
	ntask->stack_end   = ctask->stack_end;
	ntask->heap_start  = ctask->heap_start;
	ntask->heap_end    = ctask->heap_end;

	memcpy(ntask->xsave, ctask->xsave, sizeof(ctask->xsave));

	/* FIXME not sure if we should do this or not */
	ntask->elf = kmalloc(sizeof(struct elf), "fork.elf", ntask, 0);
	memcpy(ntask->elf, ctask->elf, sizeof(struct elf));

	ntask->elf->sh = kmalloc(sizeof(struct elf_section) * ctask->elf->h.e_shnum, "fork.elf.sh", ntask, 0);
	memcpy(ntask->elf->sh, ctask->elf->sh, sizeof(struct elf_section) * ctask->elf->h.e_shnum);
	
    ntask->elf->ph = kmalloc(sizeof(struct elf_segment) * ctask->elf->h.e_phnum, "fork.elf.sh", ntask, 0);
	memcpy(ntask->elf->ph, ctask->elf->ph, sizeof(struct elf_segment) * ctask->elf->h.e_phnum);

	ntask->elf->sh->seg = ntask->elf->ph;

	for(int i = 0; i < MAX_FD; i++)
		if(ctask->fps[i]) {
			ntask->fps[i] = do_dup(ctask->fps[i], ntask);
		} else {
			ntask->fps[i] = NULL;
		}

	ntask->uid = ctask->uid;
	ntask->euid = ctask->euid;
	ntask->gid = ctask->gid;
	ntask->egid = ctask->egid;

	ntask->name[0] = newpid + '0';

	//printf("do_fork[%lx]: newpid=%lx\n", me, newpid);
	//dump_task(ntask);
	ntask->state = STATE_RUNNING;

fail:
	return newpid;
}

/*
void print_stack(void *rsp)
{
	uint64_t tmp;
	printf("[rsp=%p]\n", rsp);
	return;
	if(is_valid(rsp))
		for(int i=0;i<16;i++) {
			memcpy(&tmp, (void *)((uint64_t)rsp-(i<<4)),8);
			printf("[rsp-%0x] %0lx\n", i<<4, tmp);
		}
}
*/

pid_t sys_fork(void)
{
	const int me = curtask;
	const struct task *ctask = get_task(me);
	long newpid = -1;

	if(!ctask)
		return -EINVAL;

	lock_tasks(); {
		newpid = do_fork(ctask, &ctask->tss, ctask->syscall_rip, (uint64_t)ctask->stacksave, ctask->syscall_rflags);
	} unlock_tasks();

	//printf("sys_fork: returning %lx for task %x\n", newpid, me);

	return newpid;
}

__attribute__((nonnull)) static void dump_task(const struct task *const t)
{
	printf("dump_task: pid:%u @%p this:%p ",
			t->pid, 
			(void *)t,
			(void *)t->this_task);
	printf("rip:%lx[%lx] rsp:%lx[%lx] cs:%lx ss:%lx ",
			t->tss.rip,
			get_phys_address(t->pd, t->tss.rip),
			t->tss.rsp,
			get_phys_address(t->pd, t->tss.rsp),
			t->tss.cs,
			t->tss.ss);
	printf("syscall_rip:%lx[%lx] stacksave:%p[%lx] ",
			t->syscall_rip,
			get_phys_address(t->pd,(uint64_t)t->syscall_rip),
			(void *)t->stacksave,
			get_phys_address(t->pd,(uint64_t)t->stacksave));
	printf("krnlstack:%p krnstkptr:%p\n",
			(void *)t->kernelstack,
			(void *)t->kernelsptr);

	//print_reg(&t->tss);

	/*
	printf(" code: %p -> %p ",
			t->code_start, 
			t->code_end);
	printf(" data: %p -> %p ",
			t->data_start, 
			t->data_end);
	printf(" stak: %p -> %p ",
			t->stack_start, 
			t->stack_end);
	printf(" heap: %p -> %p",
			t->heap_start, 
			t->heap_end);*/
}


void dump_tasks()
{
	for(int i = 0; i<NUM_TASKS; i++)
		if(tasks[i].state != STATE_EMPTY)
			dump_task(&tasks[i]);
}

extern unsigned long total_frames;
extern struct task **taskbm;

#define MAX_ARG

int sys_execve(const char *const file, const char *const argv[], const char *const envp[])
{
	struct task *t;
	struct elf *oelf;
	uint64_t i,offset;
	int j;
	int ret;
    pt_t *old_pt;

	if(!file || !argv || !envp) 
		return -ENOENT;
	if(!is_valid((uint8_t*)file) || !is_valid((uint8_t*)argv) || !is_valid((uint8_t*)envp)) 
		return -EFAULT;

	int argc = 0, arglen = 0;
	int envc = 0, envlen = 0;

	char **argv_new,**envp_new;

	while(argv[argc++]) ;
	while(envp[envc++]) ;

	if((argv_new = kmalloc((argc + 1) * sizeof(char *),"argv",NULL,0)) == NULL)
		return -ENOMEM;
	if((envp_new = kmalloc((envc + 1) * sizeof(char *),"envp",NULL,0)) == NULL) {
		kfree(argv_new);
		return -ENOMEM;
	}

	for(j=0;j<argc;j++) {
		if(argv[j]) {
			argv_new[j] = strdup(argv[j]);
			arglen += strlen(argv[j]);
		} else
			argv_new[j] = NULL;
	}
	argv_new[j] = NULL;

	for(j=0;j<envc;j++) {
		if(envp[j]) {
			envp_new[j] = strdup(envp[j]);
			envlen += strlen(envp[j]);
		} else
			envp_new[j] = NULL;
	}
	envp_new[j] = NULL;

	t = &tasks[curtask];
	t->state = STATE_CREATING;

	//print_mm(t->pd);

	//printf("sys_execve: %s, %p, %p\n", file, (void *)argv, (void *)envp);

	oelf = t->elf;

	//printf("sys_execve: task=%p task.elf=%p\n", (void *)t, (void *)oelf);
	//printf("sys_execve: l:%lx h:%lx fs:%p[%lx]\n",
	//		oelf->lowaddr,
	//		oelf->highaddr,
	//		(void *)oelf->page_start,
	//		oelf->frames);

	t->elf = NULL;
	kfree(oelf->ph);
	kfree(oelf->sh);
	kfree(oelf);

	//for(i = 0; i < MAX_FD; i++) {
	//	if(t->fps[i]) do_close(t->fps[i], t);
	//}

	uint8_t *code, *data;
	uint64_t clen, dlen, vaddr, daddr;
	void *tmp;

	for(i=0;i<total_frames;i++)
		if(taskbm[i] == t) 
			clear_frame((void *)(i * PAGE_SIZE));

	t->tls = NULL;
    old_pt = t->pd;
	t->pd = kmalloc_align(sizeof(pt_t), (char *)file, t, KMF_ZERO);

	strcpy((char *)&t->name, file);
	ret = do_exec(t, file, &code, &clen, &data, &dlen, &vaddr, &daddr);

	if(ret == -1) {
		printf("do_exec failed - i have no way to recover this\n");
		sti();
		while(1) hlt();
	}

	t->code_start  = (uint8_t *)vaddr;
	t->code_end    = (uint8_t *)vaddr + clen;
	t->data_start  = (uint8_t *)daddr;
	t->data_end    = (uint8_t *)daddr + dlen;
	t->stack_end   = (uint8_t *)0xc0000000UL;
	t->stack_start = (uint8_t *)((uint64_t)t->stack_end - STACK_SIZE);
	t->heap_end    = t->heap_start = (t->data_end == NULL ? t->code_end : t->data_end);

	clone_mm(kernel_pd, t->pd, t, false);

	/*
	for(offset = 0; offset < KERN_MEM; offset += PGSIZE_1G)
		if(!create_page_entry_1g(t->pd, offset, offset, PEF_P|PEF_G|PEF_W, t)) {
            printf("sys_execve: unable to map kernel pages\n");
			kfree(argv_new);
			kfree(envp_new);
            return -ENOMEM;
        }*/

	for(offset = 0; offset < STACK_SIZE; offset += PGSIZE_4K) {
		tmp = find_frame(t);
		if(!tmp || !create_page_entry_4k(t->pd, offset + (uint64_t)t->stack_start, (uint64_t)tmp, PEF_P|PEF_U|PEF_W, t)) {
			printf("sys_execve: unable to alloc page for task\n");
			kfree(argv_new);
			kfree(envp_new);
			t->pd = old_pt;
			return -ENOMEM;
		}
	}

	setup_task(t, vaddr, USER_TASK, t->pd, NULL, (uint64_t)t->stack_end - 8, t->pid);

    t->syscall_rip    = t->tss.rip;
    t->syscall_rflags = t->tss.rflags;
    t->stacksave      = (uint8_t*)t->tss.rsp;

    set_cr3(t->pd);
	free_mm(old_pt);
    write_msr(MSR_FSBASE, 0x0);

	//printf("sys_execve: rip=%lx/%lx rsp=%lx/%lx\n", 
	//		t->tss.rip, t->syscall_rip, 
	//		t->tss.rsp, (uint64_t)t->stacksave);

	void *args = do_brk(t, NULL);
	args       = do_brk(t, (void *)((uint64_t)args + arglen + envlen));

	char  *tmp_str;
	size_t tmp_len;

	tmp_str = args;

	uint64_t *stack = (uint64_t *)(t->stack_start);
	int sp          = (STACK_SIZE/sizeof(uint64_t));
	
	sp--;

	//printf("do_exec: sp=%x\n", sp);

	stack[sp--] = argc;

	for(j = 0; j < argc; j++) {
		tmp_len     = strlen(argv_new[j]) + 1;
		memcpy(tmp_str, argv_new[j], tmp_len);
		stack[sp--] = (uint64_t)tmp_str;
		tmp_str    += tmp_len;
	}
	stack[sp--] = 0;
	//printf("do_exec: sp=%x\n", sp);

	for(j = 0; j < envc; j++) {
		tmp_len     = strlen(envp_new[j]) + 1;
		memcpy(tmp_str, envp_new[j], tmp_len);
		stack[sp--] = (uint64_t)tmp_str;
		tmp_str    += tmp_len;
	}
	stack[sp--] = 0;
	//printf("do_exec: sp=%x\n", sp);

	for(int i = 0; i < 3; i++)
		stack[sp--] = 0;
	//printf("do_exec: sp=%x\n", sp);

	//printf("sys_execve: complete\n");

	kfree(envp_new);
	kfree(argv_new);
	// TODO free the rest of the tmp kernel shit

    t->state = STATE_RUNNING;

	return 0;
}

pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	printf("wait4: not implemented: %d,%p,%d,%p\n", 
			pid, (void *)status, options, (void *)rusage);
	sti();
	return -1;
}

void sys_exit_group(const int status)
{
	sys_exit(status);
}

void sys_exit(const int status)
{
	const uint64_t me    = curtask;
	struct task *const t = &tasks[curtask];

	t->state = STATE_KILLING;

	printf("sys_exit[%lx]\n", me);

	for(int i = 0; i < MAX_FD; i++)
		if(t->fps[i]) do_close(t->fps[i], t);

	t->exit_status = status;

	//dump_fsents();

	sti();

	while(1) 
        hlt();
}

uid_t sys_getuid(void)
{
	return get_task(curtask)->uid;
}

uid_t sys_getgid(void)
{
	return get_task(curtask)->gid;
}

uid_t sys_geteuid(void)
{
	return get_task(curtask)->euid;
}

uid_t sys_getegid(void)
{
	return get_task(curtask)->egid;
}

