#define _PROC_C
#include "proc.h"
#include "klibc.h"
#include "mem.h"
#include "page.h"
#include "frame.h"
#include "cpu.h"
#include "elf64.h"
#include "file.h"

uint64	curtask = 0;
unsigned long firsttask = 1;
unsigned long nosched;
struct task tasks[NUM_TASKS];
unsigned long task_lock;
unsigned long frames_lock;

const char *state_names[STATE_NUM] = {
	"STATE_EMPTY",
	"STATE_KILLING",
	"STATE_CREATING",
	"STATE_RUNNING",
	"STATE_WAIT",
	"STATE_EXECVE",
	"STATE_FORK"
};

bool switch_to(struct task *new_tsk, struct regs *r)
{
	if(!new_tsk || !new_tsk->pd) { 
		printf("error: new or new.pd NULL on new=%x\n", new_tsk);
		return false;
	}
	memcpy(r, &new_tsk->tss, sizeof(struct regs));
	write_msr(MSR_KERNEL_GSBASE, (uint64)new_tsk);
	global_tss.rsp0 = (uint64)new_tsk->kernelsptr;
	cr3_flush(new_tsk->pd);
	return true;
}

void save_state(struct task *old, struct regs *r)
{
	memcpy(&old->tss, r, sizeof(struct regs));
}

void print_reg(struct regs *r)
{
	printf(	"rax: %lx rbx: %lx rcx: %lx rdx: %lx\n"
			"rdi: %lx\n"
			"int: %0x err: %x\n"
			"rip:    %lx\n"
			"rflags: %lx\n"
			"rsp:    %lx\n"
			"cs:     %lx\n"
			"ss:     %lx\n",
			r->rax, r->rbx, r->rcx, r->rdx,
			r->rdi,
			r->int_num,
			r->error_code,
			r->rip,
			r->rflags,
			r->rsp,
			r->cs,
			r->ss);
}

bool force_sched = false;

void sched_main( struct regs *r)
{
	struct task *t;
	unsigned long i;
	unsigned long new_tsk;
	bool running;

	force_sched = false;

	lock_tasks();

	printf("sched_main: start\n");

	i = curtask + 1;
	new_tsk = 0;
	running = true;

	while(running)
	{
		//	if( i < NUM_TASKS ) {
		//		printf("sched: i=%x curtask=%x state=%s\n", i, curtask,
		//			state_names[tasks[i].state]);
		//	}

		if( i >= NUM_TASKS ) i = 0;
		else if( i == curtask ) running = false;
		else if( tasks[i].state == STATE_RUNNING 
				|| tasks[i].state == STATE_EXECVE 
				|| tasks[i].state == STATE_FORK ) running = false;
		else i++;
	}

	//printf("sched: i=%x\n", i);

	new_tsk = i;

	if( new_tsk == curtask ) {
		printf("sched: no other tasks: rip=%x rsp=%x/%x/%s\n",
				r->rip, r->rsp, 
				tasks[curtask].stacksave, 
				tasks[curtask].kernelsptr);
		unlock_tasks();
		//print_frame_stats();
		//print_kmem_stats();
		//dump_pools();
		return;
	}

	uint64 tmp;

	/*
	for(int i=0;i<4;i++) {
		memcpy(&tmp, (void *)(r->rsp-(i<<4)),8);
		printf("[rsp-%0x] %0lx (%s)\n", i<<4, tmp, find_sym((void *)tmp));
	}
	*/

	save_state(&tasks[curtask], r);

	printf("switching from: pid:%x rip:%lx (%s) rsp:%lx pd:%lx cs:%lx %s\n", 
			curtask, r->rip, find_sym((void *)r->rip),
			r->rsp, tasks[curtask].pd, r->cs,
			state_names[tasks[curtask].state]);
	//describe_mem(r->rsp);

	if(tasks[new_tsk].state == STATE_FORK) {
		printf("sched: forking from pid=%lx curpid=%lx\n", i, curtask);
		do_fork(&tasks[new_tsk], &tasks[new_tsk].tss, 
				(uint64)&tasks[new_tsk].rip, 
				(uint64)&tasks[new_tsk].stacksave, 
				(uint64)&tasks[new_tsk].rflags
				);
	}
	curtask = new_tsk;

	switch_to(&tasks[curtask], r);
	printf("switching to:   pid:%x rip:%lx (%s) rsp:%lx pd:%lx cs:%lx %s\n",
			curtask, r->rip, find_sym((void *)r->rip),
			r->rsp, tasks[curtask].pd, r->cs, 
			state_names[tasks[curtask].state]);
	//describe_mem(r->rsp);

	if(tasks[curtask].state == STATE_EXECVE) 
		tasks[curtask].state = STATE_RUNNING;

	//	if(!r->cs) {
	//		printf("r->cs == 0\n");
	//	}
	print_reg(r);

	for(i=0; i<NUM_TASKS; i++) 
	{
		if( i == curtask ) continue;	// don't touch the current task
		t = &tasks[i];
		switch(t->state) 
		{
			case STATE_KILLING:
				if(!t->tss.rip) break;
				t->tss.rip = 0;
				printf("sched_main: killing task %x during task %x\n", i, curtask);
				// FIXME if(t->pd) { free_pd(t->pd); t->pd = NULL; }
				t->state = STATE_EMPTY;
				//				print_tasks();
				break;
		}
	}

	unlock_tasks();
	printf("sched_main: done\n");
}

void sched_fail(void)
{
	printf("sched_fail()");
	while(true) hlt();
}

void print_tasks(void)
{
	unsigned long pid;

	// FIXME
	printf("gtss: curtask:%x\n", curtask);

	for(pid=0;pid<NUM_TASKS;pid++) {
		print_task(&tasks[pid]);
	}
}


void print_task(struct task *tsk)
{
	struct regs *t = &tsk->tss;

	printf("task %x rip:%x rsp:%x "
			"st: %x rax: %x rbp: %x "
			"pd: %x"
			"\n",
			tsk, t->rip, t->rsp, 
			tsk->state, t->rax, t->rbp,
			tsk->pd);
}


/* FIXME: needs to lock and find another slot for ctsk */

inline void lock_tasks(void)
{
	while(task_lock!=0) pause();
	task_lock = 1;
	nosched = 1;
}

inline void unlock_tasks(void)
{
	task_lock = 0;
	nosched = 0;
}

uint64 find_free_task(bool lock)
{
	uint64 i;

	if(lock) lock_tasks();
	for(i=1;i<NUM_TASKS;i++) // we don't use PID==0 !
	{
		if(!tasks[i].tss.rip && tasks[i].state == STATE_EMPTY) { 
			tasks[i].state = STATE_CREATING;
			unlock_tasks(); 
			return i; 
		}
	}
	if(lock) unlock_tasks();
	return -1;
}


void *add_page_task(struct task *tsk)
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

void setup_task(struct task *tsk, uint64 eip, int type, 
		pt_t *pd, const char *name, uint64 user_esp)
{
	struct regs *t = &tsk->tss;
	tsk->state = STATE_CREATING;
	tsk->this_task = tsk;
	tsk->pd = pd;

	memset(&tsk->tss, 0, sizeof(tsk->tss));
	strcpy(&tsk->name[0], name);

	t->rip = eip;
	t->rflags = 0x200;
	t->rsp = user_esp;

	switch(type)
	{
		case KERNEL_TASK:
			t->cs = (uint8)_KERNEL_CS;
			t->ss = (uint8)_KERNEL_DS;
			t->ds = t->es = t->fs = t->gs = _KERNEL_DS;
			tsk->kernelstack = (uint8 *)kmalloc(STACK_SIZE, "krnlstack", tsk);
			tsk->kernelsptr = tsk->kernelstack + STACK_SIZE;
			break;
		case CLONE_TASK:
		default:
			tsk->kernelstack = (uint8 *)kmalloc(STACK_SIZE, "krnlstack", tsk);
			tsk->kernelsptr = tsk->kernelstack + STACK_SIZE;
			t->cs = (uint8)(_USER_CS|0x03);
			t->ss = (uint8)(_USER_DS|0x03);
			t->ds = t->es = t->fs = t->gs = (uint64)(_USER_DS|0x03);
			break;
	}

	if(type != CLONE_TASK) tsk->state = STATE_RUNNING;
}

uint64 do_exec(struct task *t, const char *f, uint8 **code, uint64 *clen, uint8 **data, uint64 *dlen, uint64 *vaddr, uint64 *daddr)
{
	elf64_hdr hdr;
	elf64_phdr *phdr;
	elf64_shdr *shdr;
	struct fileh *fh;
	char buf[64];
	uint8 *tmp;
	struct elf *elf;
	int shnum, phnum;
	uint64 offset;
	//	uint64 read;

	printf("do_exec: t=%x, f=%x, code=%x, len=%x\n");

	fh = do_open(f, NULL, 0); // FIXME flags

	*code = *data = 0;
	*vaddr = *daddr = *clen = *dlen = 0;

	if(!fh) {
		printf("do_exec: can't open file\n");
		return -1;
	}

	if(do_read(fh, (uint8 *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		printf("didn't read something\n");
		goto fail;
	}

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &hdr.ei_mag, sizeof(hdr.ei_mag));

	if(buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
		printf("do_exec: not an ELF: %c%c%c%c\n", buf[0], buf[1], buf[2], buf[3]);
		goto fail;
	}

	printf("do_exec: ver:%x - %s / %s / %s[%x]: machine:%x\n",
			hdr.ei_version, 
			ELFclass[hdr.ei_class], 
			ELFdata[hdr.ei_data], 
			ELFosabi[hdr.ei_osabi],
			hdr.ei_abiversion,
			hdr.e_machine);

	if(	hdr.ei_class != ELFCLASS64 
			|| hdr.ei_data != ELFDATA2LSB 
			|| !(hdr.ei_class != ELFOSABI_SYSV 
				&& hdr.ei_class != ELFOSABI_LINUX) 
			|| hdr.e_machine != EM_X86_64 ) {
		printf("Unsupported ELF ABI, machine type, class or data\n");
		goto fail;
	}

	printf("do_exec: %s, version: %x\n", 
			ELFetype[hdr.e_type], 
			hdr.e_version);

	if(hdr.e_type != ET_EXEC) {
		printf("do_exec: unsupported e_type\n");
		goto fail;
	}

	printf("do_exec: phnum = %x shnum = %x\n", hdr.e_phnum, hdr.e_shnum);

	elf = kmalloc(sizeof(struct elf), "elf", t);
	elf->sh = kmalloc(sizeof(struct elf_section) * hdr.e_shnum, "elf_sh", t);
	elf->ph = kmalloc(sizeof(struct elf_segment) * hdr.e_phnum, "elf_ph", t);
	memcpy(&elf->h, &hdr, sizeof(elf->h));

	printf("do_exec: entry: %x, phoff: %x, shoff: %x\n", 
			hdr.e_entry, hdr.e_phoff, hdr.e_shoff);

	offset = hdr.e_phoff;

	*vaddr = *clen = *dlen = 0;

	for(phnum = 0 ; phnum < hdr.e_phnum ; phnum++ )
	{
		do_seek(fh, offset);
		do_read(fh, (uint8 *)&elf->ph[phnum].hdr, sizeof(elf64_phdr));
		offset += sizeof(elf64_phdr);
	}

	offset = hdr.e_shoff + hdr.e_shentsize;

	printf("do_exec: elf:%x elf.sh:%x elf.ph:%x\n", elf, elf->sh, elf->ph);

	for(shnum = 0 ; shnum < hdr.e_shnum; shnum++)
	{
		do_seek(fh, offset);
		do_read(fh, (uint8 *)&elf->sh[shnum].hdr, sizeof(elf64_shdr));
		offset += sizeof(elf64_shdr);
	}

	uint64 lowaddr = -1, highaddr = 0;

	for(phnum = 0 ; phnum < hdr.e_phnum ; phnum++ )
	{
		phdr = &elf->ph[phnum].hdr;

		if(phdr->p_type >= PT_MAX) continue;
		printf("do_exec: phdr[%x] %s (",
				phnum, phdr->p_type < PT_MAX ? ELFptype[phdr->p_type] : "#ERR");
		print_bits(phdr->p_flags, bits_ELF_PF, 8, 0);
		printf(") p_offset %x, sz: %x/%x, p_vaddr: %x, p_paddr: %x\n",
				phdr->p_offset, 
				phdr->p_filesz,
				phdr->p_memsz,
				phdr->p_vaddr, 
				phdr->p_paddr); 
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

	printf("do_exec lowaddr=%lx highaddr=%lx pages=%lx\n", lowaddr, highaddr, 
			((highaddr - lowaddr)/PAGE_SIZE));

	tmp = (uint8 *)find_n_frames((highaddr - lowaddr)/PAGE_SIZE, t);

	elf->lowaddr = lowaddr;
	elf->highaddr = highaddr;
	elf->page_start = tmp;
	elf->frames = (highaddr - lowaddr)/PAGE_SIZE;

	for(offset = lowaddr ; offset < highaddr ; offset += PAGE_SIZE, tmp += PAGE_SIZE)
	{
		create_page_entry_4k(t->pd, offset, (uint64)tmp, PEF_P|PEF_U|PEF_W, t);
	}

	for(phnum = 0; phnum < hdr.e_phnum ; phnum++ )
	{
		if( !(elf->ph[phnum].flags & ES_LOADME) 
				|| (elf->ph[phnum].flags & ES_LOADED)) continue;

		phdr = &elf->ph[phnum].hdr;

		if((phdr->p_flags & (PF_X|PF_R)) == (PF_X|PF_R)) {
			if(!*code) {
				*code = (uint8 *)get_phys_address(t->pd, phdr->p_vaddr);
				*clen = phdr->p_memsz;
				*vaddr = phdr->p_vaddr;
			}

			do_seek(fh, phdr->p_offset);
			do_read(fh, (uint8 *)get_phys_address(t->pd, phdr->p_vaddr), 
					phdr->p_filesz);
		} else if ((phdr->p_flags & PF_R) == PF_R) {
			if(!*data) {
				*data = (uint8 *)get_phys_address(t->pd, phdr->p_vaddr);
				*dlen = phdr->p_memsz;
				*daddr = phdr->p_vaddr;
			}

			do_seek(fh, phdr->p_offset);
			do_read(fh, (uint8 *)get_phys_address(t->pd, phdr->p_vaddr), 
					phdr->p_filesz);
		} else {
		}
	}

	for(shnum = 0 ; shnum < hdr.e_shnum ; shnum++)
	{
		shdr = &elf->sh[shnum].hdr;

		if(shdr->sh_type == SHT_NULL) continue;
		printf("do_exec: shdr[%x:%x] %s (",
				shnum, 
				shdr,
				ELFshtype[shdr->sh_type]);
		print_bits(shdr->sh_flags, bits_SHF, 8, 0);
		printf(") sh_addr: %x, sh_offset: %x, sh_size: %x\n",
				shdr->sh_addr,
				shdr->sh_offset, 
				shdr->sh_size);
		if(shdr->sh_type != SHT_PROGBITS ||
				(shdr->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) != 
				(SHF_ALLOC|SHF_EXECINSTR)) {
			continue;
		} else if (*vaddr) {
			//	printf("do_exec: double shdr\n");
			continue;
		} else {
			//	*vaddr = shdr->sh_addr;
			continue;
		}
	}

	*vaddr = elf->h.e_entry;

	do_close(fh, t);
	t->elf = elf;
	return 0;

	//fail2:
	kfree(elf->ph);
	kfree(elf->sh);
	kfree(elf);
fail:
	do_close(fh, t);
	return -1;
}

struct task *get_task(uint64 i)
{
	if(i > NUM_TASKS) goto fail;

	switch(tasks[i].state)
	{
		case STATE_EMPTY:
		case STATE_KILLING:
		case STATE_CREATING:
			goto fail;
			break;
		default:
			return &tasks[i];
			break;
	}

fail:
	return NULL;
}

/* FIXME: clone filehandles and shit */

void do_fork(struct task *ctask, struct regs *r, uint64 rip, 
		uint64 rsp, uint64 rflags)
{
	uint64 newpid;
	struct task *ntask;
	pt_t *newpd;

	printf("do_fork: pid=%lx rip=%lx/%lx/%lx, rsp=%lx/%lx/%lx, rflags=%lx/%lx\n", 
			curtask,
			rip, ctask->tss.rip, ctask->rip,
			rsp, ctask->tss.rsp, ctask->stacksave,
			rflags, ctask->tss.rflags
			);

	newpid = find_free_task(false);

	if(newpid == -1UL) goto fail;
	ntask = &tasks[newpid];
	
	newpd = (pt_t *)kmalloc_align(sizeof(pt_t), "fork.pml4", ntask);
	if(!newpd) {
		ntask->state = STATE_EMPTY;
		newpid = -1UL;
		goto fail;
	}

	clone_mm(ctask->pd, newpd, ntask);
	setup_task(ntask, rip, CLONE_TASK, newpd, (char *)&ctask->name, ntask->tss.rsp);
	memcpy(&ntask->tss, r, sizeof(struct regs));
	memcpy(ntask->kernelstack, ctask->kernelstack, STACK_SIZE);

	ntask->tss.rax = 0x0;
	ntask->tss.rflags = ctask->rflags;
	ntask->tss.rip = ctask->rip;
	ntask->tss.rsp = ctask->stacksave;
	ntask->rip = ctask->rip;
	ntask->rflags = ctask->rflags;
	ntask->stacksave = ctask->stacksave;
	ntask->newpid = 0;
	ntask->tss.cs = _USER_CS|0x03;
	ntask->tss.ds = ntask->tss.es = ntask->tss.fs = ntask->tss.ss = _USER_DS|0x03;
	ntask->state = STATE_RUNNING;

fail:
	printf("do_fork: newpid=%lx\n", newpid);
	ctask->newpid = newpid;
	ctask->state = STATE_RUNNING;
}

void print_stack(void *rsp)
{
	uint64 tmp;
	printf("[rsp=%lx]\n", rsp);
	for(int i=0;i<16;i++) {
	    memcpy(&tmp, (void *)(rsp-(i<<4)),8);
	    printf("[rsp-%0x] %0lx\n", i<<4, tmp);
	}
}

uint64 sys_fork()
{
	//uint64 newpid;
	struct task *ctask = &tasks[curtask];
	//struct task *ntask;
	//pt_t *newpd;
	//uint64 rflags = ctask->rflags;
	//uint64 rip = ctask->rip;
	
	printf("sys_fork: pid=%lx state=%s rip=%lx\n", 
			curtask, 
			state_names[ctask->state],
			ctask->rip
			);

	ctask->state = STATE_FORK;

	printf("sys_fork: sleeping\n");

	sti();
	while(ctask->state == STATE_FORK) pause();
	cli();

	ctask = &tasks[curtask];
	printf("sys_fork: woken: newpid=%lx\n", ctask->newpid);

	return ctask->newpid;

	/*

	printf("sys_fork: RFLAGS: %x, RIP: %x, curtask:%x(stacksave:%lx)\n", 
				rflags, rip, curtask, ctask->stacksave);
	uint64 tmp;
	for(int i=0;i<4;i++) {
	    memcpy(&tmp, (void *)(ctask->stacksave-(i<<4)),8);
	    printf("[rsp-%0x] %0lx\n", i<<4, tmp);
	}

	newpid = find_free_task();

	if(newpid == -1UL) goto fail;

	ntask = &tasks[newpid];

	for(int i=0; i<MAX_FD;i++ )
	{
		if(ctask->fps[i]) ntask->fps[i] = do_dup(ctask->fps[i], ntask);
	}

	newpd = (pt_t *)kmalloc_align(sizeof(pt_t), "fork.pml4", ntask);
	if(!newpd) goto fail2;

	//	printf("sys_fork: clone_mm (%x)\n", ctask->pd);

	if(!ctask->pd) {
		printf("ERROR: curtask->pd == NULL!\n");
		goto fail3;
	}

	clone_mm(ctask->pd,newpd,ntask);

	//	printf("sys_fork: setup_task\n");

	setup_task(ntask, rip, USER_TASK, newpd, 
			(char *)&ctask->name, 
			(uint64)(ctask->stacksave)); // FIXME: user_esp

	// TODO: how the fuck to do this?
	// memcpy(&ntask->tss, &r, sizeof(struct regs));

	ntask->tss.rax = 0x0;			// return value for new process
	ctask->tss.rax = newpid;
	ntask->tss.rflags = rflags;
	ntask->tss.rsp = (uint64)(ctask->stacksave);
	ntask->stacksave = ctask->stacksave;
	ntask->tss.rip = rip;
	ntask->tss.cs = ctask->tss.cs;
	ntask->tss.ss = ctask->tss.ss;
	ntask->tss.ds = ctask->tss.ds;
	ntask->tss.es = ctask->tss.es;
	ntask->tss.fs = ctask->tss.fs;
	ntask->tss.gs = ctask->tss.gs;

	ntask->state = STATE_RUNNING;

	printf("sys_fork: newpid=%x stack=%lx[%lx] / %lx[%lx]\n", 
			newpid,
			ctask->stacksave,
			get_phys_address(ctask->pd, ctask->stacksave),
			ntask->stacksave,
			get_phys_address(ntask->pd, ntask->stacksave),
			);

	return newpid;

fail3:
	kfree(newpd);
fail2:
	ntask->state = STATE_EMPTY;
fail:
	return -1;
	*/
}

void dump_task(struct task *t)
{
	printf("dump_task: task '%s' @ %lx\n",
			t->name, t);
	printf(" code: %0lx -> %0lx\n",
			t->code_start, 
			t->code_end);
	printf(" data: %0lx -> %0lx\n",
			t->data_start, 
			t->data_end);
	printf(" stak: %0lx -> %0lx\n",
			t->stack_start, 
			t->stack_end);
	printf(" heap: %0lx -> %0lx\n",
			t->heap_start, 
			t->heap_end);
}

uint64 sys_execve(const char *file, char *const argv[], char *const envp[])
{
	extern unsigned long total_frames;
	extern struct task **taskbm;
	struct task *t;
	struct elf *oelf;
	uint64 i,offset;
	uint64 ret;

	if(!file) return -ENOENT;

	cli();

	t = &tasks[curtask];
	t->state = STATE_CREATING;

	printf("sys_execve: %s, %lx, %lx\n", file, argv, envp);

	oelf = t->elf;

	printf("sys_execve: task=%lx task.elf=%lx\n", t, oelf);
	printf("sys_execve: l:%lx h:%lx fs:%lx[%lx]\n",
			oelf->lowaddr,
			oelf->highaddr,
			oelf->page_start,
			oelf->frames);

	t->elf = NULL;
	clear_n_frames(oelf->page_start, oelf->frames);
	kfree(oelf->ph);
	kfree(oelf->sh);
	kfree(oelf);

	for(i = 0; i < MAX_FD; i++) {
		if(t->fps[i]) do_close(t->fps[i], t);
	}

	uint8 *code, *data;
	uint64 clen, dlen, vaddr, daddr;
	void *tmp;

	for(i=0;i<total_frames;i++)
	{
		if(taskbm[i] == t) clear_frame((void *)(i * PAGE_SIZE));
	}

	ret = do_exec(t, file, &code, &clen, &data, &dlen, &vaddr, &daddr);

	if(ret) {
		printf("do_exec failed - i have no way to recover this\n");
		sti();
		while(1) hlt();
	}

	t->code_start = (uint8 *)vaddr;
	t->code_end = (uint8 *)vaddr + clen;
	t->data_start = (uint8 *)daddr;
	t->data_end = (uint8 *)daddr + dlen;
	t->stack_end = (uint8 *)0xc0000000UL;
	t->stack_start = (uint8 *)((uint64)t->stack_end - PGSIZE_4K);
	t->heap_end = t->heap_start = (t->data_end == NULL ? t->code_end : t->data_end);

	tmp = find_frame(t);

	t->pd = kmalloc_align(sizeof(pt_t), (char *)file, t);
	for(offset = 0; offset < (0x100000*512); offset += 0x200000)
		create_page_entry_2m(t->pd, offset, offset, PEF_P|PEF_G|PEF_W, t);

	create_page_entry_4k(t->pd, (uint64)t->stack_start, (uint64)tmp, 
			PEF_P|PEF_U|PEF_W, t);

	setup_task(t, vaddr, USER_TASK, t->pd, file, (uint64)t->stack_end - 8);

	printf("execve: complete. sleep\n");

	t->state = STATE_EXECVE;

	sti();
	while(1) hlt();

	return 0;
}

uint64 sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	printf("wait4: not implemented\n");
	sti();
	while(1) hlt();
}

void sys_exit(int status)
{
	int i;

	struct task *t = &tasks[curtask];
	for(i = 0; i < MAX_FD; i++) {
		if(t->fps[i]) do_close(t->fps[i], t);
	}

	// TODO: free ram here or elsewhere?

	t->state = STATE_KILLING;
	sti();
	while(1) pause();
}
