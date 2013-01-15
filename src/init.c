#define _INIT_C
#include "klibc.h"
#include "mboot.h"
#include "acpi.h"
#include "ppp.h"
#include "slip.h"
#include "frame.h"
#include "mem.h"
#include "intr.h"
#include "page.h"
#include "dev.h"
#include "cpu.h"
#include "proc.h"
#include "pci.h"
#include "ram.h"
#include "ramfs.h"
#include "syscall.h"
#include "net.h"
#include "ip.h"

extern unsigned long firsttask, tick, task_lock, frames_lock;
extern unsigned short *vga;
extern struct phys_mem_slot phys_mem_list[MAX_PHYS_MEM_SLOTS];
extern bool memdebug;
extern unsigned long high_mem_start, top_of_mem, free_page_size, total_frames;
extern unsigned long kernel_ds_end, nosched;
extern unsigned long *pagebm;
extern struct task **taskbm;
extern pt_t *kernel_pd;
extern unsigned long mb_magic;
extern multiboot_info_t *mb_struct;
extern uint64 num_kern_pools, pool_page_num;
extern bool mem_init;
bool boot_done = false;

void setup_vga(void)
{
	vga = (unsigned short *)0xb8000;
	cls();
}


void setup_pic(void)
{
	outportb(0x20, 0x11);
	outportb(0xA0, 0x11);
	outportb(0x21, 0x20);
	outportb(0xA1, 0x28);
	outportb(0x21, 0x04);
	outportb(0xA1, 0x02);
	outportb(0x21, 0x01);
	outportb(0xA1, 0x01);
	outportb(0x21, 0x0);
	outportb(0xA1, 0x0);
}

uint64 crap_gdt[] = {
	0x0,
	0x008f9a000000ffff,
	0x00af9a000000ffff,
	0x00cf92000000ffff,
	0x00cffe000000ffff,
	0x00cff2000000ffff,
	0x00cff2000000ffff,
	0x00CF9a000000ffff
};

void setup_gdt(void)
{
	unsigned long tss_p;

	gdtp.limit = (uint16)(sizeof(gdt) - 1);
	gdtp.base = (unsigned long)&gdt;
	tss_p = (unsigned long)(&global_tss);

	memset((char *)&gdt, 0, sizeof(gdt));

	gdt_set_gate(_NULL_CS	,0,0,0,0,0);

	gdt_set_gate(_KERNEL_CS	,0,-1,0,(uint8)(GTF_R|GTF_P|GTF_G|GTF_L),	GDT_TYPE_CS);
	gdt_set_gate(_KERNEL_DS	,0,-1,0,(uint8)(GTF_W|GTF_P|GTF_G),			GDT_TYPE_DS);

	gdt_set_gate(_USER32_CS, 0,-1,0x3,(uint8)(GTF_R|GTF_P|GTF_D|GTF_G),	GDT_TYPE_CS);
	gdt_set_gate(_USER32_DS, 0,-1,0x3,(uint8)(GTF_W|GTF_P|GTF_B|GTF_G),	GDT_TYPE_DS);

	gdt_set_gate(_USER_CS	,0,-1,0x3,(uint8)(GTF_R|GTF_P|GTF_G|GTF_L),	GDT_TYPE_CS);
	gdt_set_gate(_USER_DS	,0,-1,0x3,(uint8)(GTF_W|GTF_P|GTF_G),		GDT_TYPE_DS);
	//memcpy((char *)&gdt, (const char *)crap_gdt, sizeof(crap_gdt));
	gdt_set_gate(_TSS_CS	,tss_p,(uint32)sizeof(global_tss),0x0,GTF_P,GDT_TYPE_TSSA);
	gdt_flush();
}


void setup_ldt(void)
{
	idtp.limit = (uint16)(sizeof(idt)-1);
	idtp.base = (unsigned long)&idt;

	(void)memset((char *)&idt, 0, sizeof(idt));

	idt_set_gate(0x0, (unsigned long)_isr0, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1, (unsigned long)_isr1, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x2, (unsigned long)_isr2, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x3, (unsigned long)_isr3, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x4, (unsigned long)_isr4, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x5, (unsigned long)_isr5, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x6, (unsigned long)_isr6, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x7, (unsigned long)_isr7, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x8, (unsigned long)_isr8, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x9, (unsigned long)_isr9, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0xa, (unsigned long)_isr10, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0xb, (unsigned long)_isr11, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0xc, (unsigned long)_isr12, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0xd, (unsigned long)_isr13, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0xe, (unsigned long)_isr14, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0xf, (unsigned long)_isr15, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x10, (unsigned long)_isr16, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x11, (unsigned long)_isr17, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x12, (unsigned long)_isr18, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x13, (unsigned long)_isr19, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x14, (unsigned long)_isr20, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x15, (unsigned long)_isr21, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x16, (unsigned long)_isr22, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x17, (unsigned long)_isr23, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x18, (unsigned long)_isr24, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x19, (unsigned long)_isr25, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1a, (unsigned long)_isr26, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1b, (unsigned long)_isr27, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1c, (unsigned long)_isr28, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1d, (unsigned long)_isr29, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1e, (unsigned long)_isr30, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x1f, (unsigned long)_isr31, _KERNEL_CS, GDT_TYPE_TRAP, 0);
	idt_set_gate(0x20, (unsigned long)_isr32, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x21, (unsigned long)_isr33, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x22, (unsigned long)_isr34, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x23, (unsigned long)_isr35, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x24, (unsigned long)_isr36, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x25, (unsigned long)_isr37, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x26, (unsigned long)_isr38, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x27, (unsigned long)_isr39, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x28, (unsigned long)_isr40, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x29, (unsigned long)_isr41, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x2a, (unsigned long)_isr42, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x2b, (unsigned long)_isr43, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x2c, (unsigned long)_isr44, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x2d, (unsigned long)_isr45, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x2e, (unsigned long)_isr46, _KERNEL_CS, GDT_TYPE_INT, 0);
	idt_set_gate(0x2f, (unsigned long)_isr47, _KERNEL_CS, GDT_TYPE_INT, 0);

	//	idt_set_gate(0x80, (unsigned long)int80_handler, _KERNEL_CS, 0xf, 0);

	idt_flush();
}


// FIXME

uint8	kernel_stack[STACK_SIZE*2];

void setup_tss(void)
{
	(void)memset((char *)&global_tss, 0, sizeof(global_tss));
	tss_flush(_TSS_CS);
}


void setup_mem(unsigned long magic, multiboot_info_t *mbi)
{
	uint64 i=0,j=0;
	unsigned long tmp;
	struct phys_mem_slot *pm = NULL;
	mem_init = false;

	if( magic != MULTIBOOT_BOOTLOADER_MAGIC ) {
		printf("PANIC: bad magic: %x\n", magic);
		while(true) hlt(); 
	}
	printf("MB: flags=%x, boot_device=%x", mbi->flags, mbi->boot_device);
	if(CHECK_FLAG(mbi->flags,2)) {
		printf(", cmd_line=%s", mbi->cmdline);
	}
	printf("\n");
	if(CHECK_FLAG(mbi->flags,6)) {
		memory_map_t *mm;
		for( mm = (memory_map_t *)(uint64)mbi->mmap_addr;
				(unsigned long)mm < mbi->mmap_addr + mbi->mmap_length;
				mm = (memory_map_t *)((unsigned long)mm + mm->size + 
					sizeof(mm->size)) )
		{
			printf("MM:\t%0x - %0x\t(%0x)\t%x\n",
					mm->base_addr_low,
					mm->base_addr_low + mm->length_low,
					mm->length_low,
					mm->type);
			if( mm->type == 1 ) {
				add_to_useable_mem((void *)(uint64)mm->base_addr_low, mm->length_low);
			}
		}

	} else {
		printf("PANIC: no memory map!: %x\n", mbi->mmap_addr);
		while(true) hlt();
	}

	pm = (struct phys_mem_slot *)&phys_mem_list[i];

	while( pm->len )
	{
		printf("RAM: phys: %0lx to %0lx\n", pm->from, pm->to);

		if(pm->from < (void *)&end_of_kernel 
				&& pm->to > (void *)&end_of_kernel) { 
			high_mem_start = (uint64)&end_of_kernel; 
		}
		top_of_mem = (uint64)pm->to;

		pm = &phys_mem_list[++i];
	}

	kernel_ds_end = high_mem_start;
	printf("RAM: high_mem_start: %x, ", high_mem_start);
	printf("top_of_mem: %x\n", top_of_mem);
	free_page_size = (total_frames = top_of_mem/PAGE_SIZE) / 64;

	printf("RAM: free_page_size: %lx, ", free_page_size);
	printf("total_frames = %lx, ", total_frames);
	printf("end_of_kernel = %lx\n", &end_of_kernel);

	taskbm = NULL;
	pagebm = NULL;
	num_kern_pools = 0;

	kernel_pd = (pt_t *) kmalloc_align(sizeof(pt_t),"kernel_pd",NULL);

	if(kernel_pd == NULL) {
		printf("PANIC: failed to allocate kernel_pd\n");
		while(true) hlt(); 
	} else {
		printf("RAM: kernel_pd created at %x len=%x\n", kernel_pd, sizeof(pt_t));
	}
	memset(kernel_pd, 0, sizeof(pt_t));

	for(j=0;j<top_of_mem;j+=PGSIZE_2M)
	{
		create_page_entry_2m(kernel_pd, j, j, PEF_P|PEF_W|PEF_G, NULL);
	}

	cr3_flush(kernel_pd);
	printf("RAM: kernel_pd installed\n");

	pagebm = (unsigned long *) kmalloc(free_page_size*8,"pagebm",NULL);
	if(pagebm == 0) {
		printf("PANIC: failed to allocate pagebm\n");
		while(true) hlt();
	}
	memset((char *)pagebm,0,free_page_size*8);

	printf("RAM: pagebm at %lx with %lu entries using %lu bytes\n", 
			pagebm, free_page_size,
			free_page_size*8);

	taskbm = (struct task **) kmalloc(total_frames*8,"taskbm",NULL);
	if(!taskbm) {
		printf("PANIC: failed to allocate taskbm\n");
		while(true) hlt();
	}
	memset((char *)taskbm,-1,total_frames*8);
	printf("RAM: taskbm at %lx with %lu entries using %lu bytes\n", 
			taskbm, total_frames,
			free_page_size*64*8);

	if(taskbm) {
		tmp = (uint64)taskbm + (total_frames * 8);
	} else {
		tmp = (uint64)pagebm + (free_page_size * 8);
	}

	for(i=0;i<top_of_mem;i+=PAGE_SIZE)
		if(!is_useable((void *)i) || i <= tmp ) 
			set_frame((void *)i);

	if(KERN_POOLS < 2) 
	{
		printf("PANIC: not enough KERN_POOLS\n");
		while(true) hlt();
	}

	memset(&kern_pool, 0, sizeof(kern_pool));

	printf("kern_pool: cleared\n");
	pool_page_num = 16;

	for(i=0;i<KERN_POOLS;i++)
	{
		do_one_pool(NULL);//i, &num);
	}

	mem_init = true;
}


void setup_pit(uint32 freq)
{
	uint32 req = (1193180 / freq);
	unsigned char l = (unsigned char)(req & 0xff);
	unsigned char h = (unsigned char)((req>>8) & 0xff);

	outportb(0x43, (unsigned char)0x36);

	outportb(0x40, l);
	outportb(0x40, h);
}

void setup_serial(unsigned short port, uint32 speed)
{
	uint32 div = 115200/speed;

	outportb(port+SER_INTEN,	0x00);					// turn interupts off
	outportb(port+SER_LCR,		(uint8)SER_LCR_DLAB);	// enable DLAB
	outportb(port+SER_LSB_DIV,	(uint8)div & 0xff);				// lo byte 115200
	outportb(port+SER_MSB_DIV,	(uint8)(div>>8));			// high byte
	outportb(port+SER_LCR,		SER_LCR_8);			// 8n1
	outportb(port+SER_FCR,		SER_FCR_ENABLE);		// irq on
	outportb(port+SER_MCR,		(uint8)SER_MCR_DTR|SER_MCR_RTS);

	//	printf("ser: port %x set to %d\n", port, speed);
	
}

/*
   uint8	task1[] = { 
   0x66,0x87,0xDB,
   0xE8,0x05,0x00,0x00,0x00,
   0xE9,0xF3,0xFF,0xFF,0xFF,
   0x0F,0x05,
   0xC3        
   };
   */
extern void task1(void);
extern uint64 task1_end,task2_end;

//unsigned char idle_task[] = {
//	0xE9, 0xFB, 0xFF, 0xFF, 0xFF, // jmp dword 0
//	0xAF // scasd ??
//};

unsigned char idle_task[] = {
	0xF4, // HLT
	0xE9, 0xFA, 0xFF, 0xFF, 0xFF // JMP
};

void task2(void);

struct task *init_task;

void create_tasks(void)
{
	uint8 *tmp,*tmp2;
	//uint8 *usersp;
	//uint64 len = 0;
	uint64 vaddr, offset, daddr;
	uint8 *code, *data;
	uint64 clen, dlen;
	pt_t *idle_pd;
	pt_t *pd;
	pt_t *pd2;

	memset(tasks, 0, sizeof(struct task) * NUM_TASKS);

	idle_pd = kmalloc_align(sizeof(pt_t),"idle.pml4", &tasks[0]);
	pd = kmalloc_align(sizeof(pt_t),"task0.pml4", &tasks[1]);
	pd2 = kmalloc_align(sizeof(pt_t),"task1.pml4", &tasks[2]);

	code = data = NULL;
	clen = dlen = 0;
	vaddr = 0;
	init_task = &tasks[1];
	init_task->pd = pd;

	for(offset = 0; offset < (0x100000*512); offset += 0x200000)
		create_page_entry_2m(pd, offset, offset, PEF_P|PEF_G|PEF_W, init_task);

	printf("calling do_exec\n");
	do_exec(init_task, "/init", &code, &clen, &data, &dlen, &vaddr, &daddr);
	printf("done\n");

	printf("create_tasks: /init : code=%x[%x], data=%x[%x], vaddr=%x\n", code, clen, data, dlen, vaddr);
	/*
	   offset = 0;

	   while(code && offset <= (clen)) {
	   if( (clen - offset) >= PGSIZE_2M) {
	   create_page_entry_2m(pd, vaddr + offset,
	   (uint64)code + offset, PEF_P|PEF_U|PEF_W, init_task);
	   offset += PGSIZE_2M;
	   } else {
	   create_page_entry_4k(pd, vaddr + offset, 
	   (uint64)code + offset, PEF_P|PEF_U|PEF_W, init_task);
	   offset += PGSIZE_4K;
	   }
	   }

	   offset = 0;

	   while(data && offset <= dlen) {
	   create_page_entry_4k(pd, daddr + offset,
	   (uint64)data + offset, PEF_P|PEF_U|PEF_W, init_task);
	   offset += PGSIZE_4K;
	   }
	   */

	//print_mm(pd);

	init_task->code_start = (uint8 *)vaddr;
	init_task->code_end = (uint8 *)vaddr + clen;
	init_task->data_start = (uint8 *)daddr;
	init_task->data_end = (uint8 *)daddr + dlen;
	init_task->stack_end = (uint8 *)0xc0000000UL;
	init_task->stack_start = (uint8 *)((uint64)init_task->stack_end - PGSIZE_4K);
	init_task->heap_end = init_task->heap_start = (init_task->data_end == NULL ? init_task->code_end : 
			init_task->data_end);

	tmp = (void *)find_frame(init_task);

	create_page_entry_4k(pd, (uint64)init_task->stack_start, (uint64)tmp, PEF_P|PEF_U|PEF_W, init_task);
	setup_task(init_task, vaddr, USER_TASK, pd, "task0", (uint64)init_task->stack_end - 8);

	//clone_mm(pd, pd2);
	//setup_task(&tasks[2], USER_CODE_START, USER_TASK, pd2, "task1", USER_RSP);

	/* idle task runs in kernel mode so is special */

	for(offset = 0; offset < (0x100000*32); offset += PGSIZE_2M)
		create_page_entry_2m(idle_pd,offset,offset,PEF_W|PEF_P|PEF_G, &tasks[0]);
	tmp = find_frame(&tasks[0]);

	memcpy(tmp, &idle_task, sizeof(idle_task)); 

	tmp2 = find_frame(&tasks[0]);
	//print_mm(idle_pd);

	setup_task(&tasks[0], (uint64)tmp, KERNEL_TASK, idle_pd, "idle", (uint64)tmp2);

	tasks[0].state = STATE_RUNNING;
}

extern void sysenter(void);

struct _STAR {
	uint32	syscall_eip;
	uint16	syscall_csss;
	uint16	sysret_csss;
} __attribute__((packed));

typedef union {
	struct _STAR a;
	uint64 b;
} __attribute__((packed)) STAR;

void setup_msr()
{
	STAR star;

	star.a.syscall_eip = 0x0;
	star.a.syscall_csss = _KERNEL_CS;
	star.a.sysret_csss = (uint16)(_USER32_CS|0x3);

	write_msr(MSR_LSTAR, (uint64)sysenter);	
	write_msr(MSR_STAR, star.b);
	write_msr(MSR_SFMASK, 0x200);			// disable interrupts
}

void gousermode(uint64,uint64,uint64,uint64,uint64);

#define	_cpuid(func,ax,bx,cx,dx) \
	__asm__ __volatile__("cpuid":"=a"(ax),"=b"(bx),"=c"(cx),"=d"(dx):"a"(func));

struct _APICbar {
	unsigned res0:8;
	unsigned bsc:1;
	unsigned res1:2;
	unsigned ae:1;
	uint64 aba:40;
	unsigned res2:12;
} __attribute__((packed));

typedef union {
	struct _APICbar a;
	uint64 b;
} __attribute__((packed)) APICbar;

#define CPUID_1GBPG	0x04000000

void cpu_init()
{
	uint32 ret[4];
	unsigned char id[13];
	struct cpu *cpu = &cpus[0];
	APICbar ab;
	uint64 apic_aba;

	_cpuid(0x0, ret[0], ret[1], ret[2], ret[3]);

	memcpy(&id[0], &ret[1], 4);
	memcpy(&id[4], &ret[3], 4);
	memcpy(&id[8], &ret[2], 4);
	id[12] = '\0';

	printf("cpu_init: cpu[0]: \"%s\"\n", id);


	ab.b = read_msr(MSR_APIC_BAR);
	printf("cpu_init: MSR_APIC_BAR: bsc:%x, ae:%x, ", ab.a.bsc, ab.a.ae, ab.a.aba);
	apic_aba = ab.a.aba << 12;
	printf("aba:%x\n", apic_aba);
	ab.a.ae = 1;
	write_msr(MSR_APIC_BAR, ab.b);

	_cpuid(0x1, ret[0], ret[1], ret[2], ret[3]);
	num_cpus = ((ret[1] & 0x00ff0000)>>16);
	if(!num_cpus) num_cpus++;
	printf("cpu_init: CPU Count:%x\n",num_cpus); 
	printf("cpu_init: cpu[0]: ");
	printf("stp:%x,", (cpu->stepping = (ret[0] & 0x0000000f)));
	printf("mod:%x,", (cpu->model = (((ret[0] & 0x000000f0)>>4)|
					((ret[0] & 0x000f0000)>>16))));
	printf("fam:%x,", (cpu->family = ((((ret[0] & 0x00000f00)>>8)|
						((ret[0] & 0x00f00000)>>20)))));
	printf("id:%x,", (cpu->apic_id = ((ret[1] & 0xff000000)>>24)));
	printf("APIC:%x\n", ((ret[3] & (1<<9)))?1:0);

	_cpuid(0x80000001, ret[0], ret[1], ret[2], ret[3]);
}

void pci_init()
{
	unsigned int i,j,z;
	uint32 vend, dev;
	struct pci_dev *ndev;

	printf("pci_init: probing\n");
	for(z = 0; z<256; z++) {
		vend = pci_read_conf16(z,0,0,PCI_VENDOR_ID);
		if( vend != 0xffff ) {
			for(i = 0; i<256; i++) {
				vend = pci_read_conf16(z,i,0,PCI_VENDOR_ID);
				if( vend != 0xffff ) {
					for(j = 0; j<256; j++) {
						vend = pci_read_conf16(z,i,j,PCI_VENDOR_ID);
						if(vend == 0xffff) { j = 256; continue; }

						dev = pci_read_conf16(z,i,j,PCI_DEVICE_ID);
						if(dev == 0xffff) { j = 256; continue; }

						ndev = add_pci_device(z,i,j);
					}
				}
			}
		}
	}
	printf("pci_init: probing complete\n");
}

void dev_init()
{
	uint64 i;

	printf("dev_init: ");
	add_dev(DEV_ID(CON_MAJOR,CON_MINOR), DEV_CHAR, 
			&console_char_ops, "con", NULL);
	printf("con ");
	for(i=0;i<NUM_RD;i++) 
	{
		add_dev(DEV_ID(RD_MAJOR,RD_0_MINOR+i), DEV_BLOCK, 
				&ram_block_ops, "ram", NULL);
		printf("ram(%x) ", i);
	}
	add_dev(DEV_ID(SER_MAJOR,SER_0_MINOR), DEV_CHAR,
			&serial_char_ops, "ser", NULL);
	printf("ser(1) ", i);
	printf("\n");
}

void proto_init()
{
	printf("proto_init: ");
	add_dev(NETPROTO_IP, DEV_PROTO, &ip_proto_ops, "ip", NULL);
	printf("ip ");
	printf("\n");
}

void net_init()
{
	return;

	printf("net_init: ");
	//	add_dev(NETDEV_PPP, DEV_NET, &ppp_net_ops, "ppp");
	//	printf("ppp ");
	//	add_dev(NETDEV_SLIP, DEV_NET, &slip_net_ops, "slip");
	//	printf("slip ");
	printf("\n");
}

void fs_init()
{
	printf("fs_init: ");
	add_dev(0, DEV_FS, &ramfs_ops, "ramfs", NULL);
	printf("ramfs ");
	printf("\n");
}

void syscall_init()
{
	int i;

	printf("syscall_init: ");

	for(i=0;i<MAX_SYSCALL;i++)
	{
		syscall_table[i] = (uint64)sys_unimp;
	}

	syscall_table[SYSCALL_READ] = (uint64)sys_read;
	syscall_table[SYSCALL_WRITE] = (uint64)sys_write;
	syscall_table[SYSCALL_OPEN] = (uint64)sys_open;
	syscall_table[SYSCALL_CLOSE] = (uint64)sys_close;

	syscall_table[SYSCALL_BRK] = (uint64)sys_brk;

	//syscall_table[SYSCALL_IOCTL] = (uint64)sys_ioctl;

	syscall_table[SYSCALL_PAUSE] = (uint64)sys_pause;

	syscall_table[SYSCALL_GETPID] = (uint64)sys_getpid;

	syscall_table[SYSCALL_SOCKET] = (uint64)sys_socket;

	syscall_table[SYSCALL_ACCEPT] = (uint64)sys_accept;
	syscall_table[SYSCALL_BIND] = (uint64)sys_bind;
	syscall_table[SYSCALL_LISTEN] = (uint64)sys_listen;

	syscall_table[SYSCALL_FORK] = (uint64)sys_fork;

	syscall_table[SYSCALL_EXECVE] = (uint64)sys_execve;
	syscall_table[SYSCALL_EXIT] = (uint64)sys_exit;
	syscall_table[SYSCALL_WAIT4] = (uint64)sys_wait4;
	syscall_table[SYSCALL_KILL] = (uint64)sys_kill;

	syscall_table[SYSCALL_TIME] = (uint64)sys_time;

	printf("done\n");
}

void main(unsigned long magic, multiboot_info_t *mbd)
{
	//int i;
	struct net_dev *nd;
	struct char_dev *cd;
	struct net_proto *np;

	//memdebug = true;

	task_lock = nosched = tick = curtask = 0;
	firsttask = 1;
	devs = NULL;
	netdevs = NULL;

	setup_vga();
	setup_serial(COM1, 115200);
	setup_serial(COM2, 115200);
	printf("FailOS\n");
	setup_mem(mb_magic, mb_struct);
	printf("init: GDT, ");
	setup_gdt();
	printf("PIC, ");
	setup_pic();
	printf("LDT, ");
	setup_ldt();
	printf("TSS, ");
	setup_tss();
	printf("PIT, ");
	setup_pit(100);
	printf("MSR, ");
	setup_msr();
	printf("done.\n");
	//dump_taskbm();
	cpu_init();
	proto_init();
	pci_init();
	dev_init();
	fs_init();
	net_init();
	syscall_init();

	do_mount(NULL, "/", &ramfs_ops);

	nd = find_dev(NETDEV_SLIP, DEV_NET);
	cd = find_dev(DEV_ID(SER_MAJOR, SER_0_MINOR), DEV_CHAR);
	np = find_dev(NETPROTO_IP, DEV_PROTO);

	//printf("init: %x %x %x\n", nd, cd, np);

	init_netdev(nd, cd, DEV_CHAR, np);
	acpi_probe();

	//while(kmalloc(1024*1024*10,""));

	//printf("x:%x lx:%lx 0lx:%0lx\n",1,1,1);

	create_tasks();
	curtask = firsttask = 1;

	write_msr(MSR_KERNEL_GSBASE, (uint64)&tasks[firsttask]);
	global_tss.rsp0 = (uint64)tasks[firsttask].kernelsptr;
	tasks[firsttask].state = STATE_RUNNING;

	//dump_taskbm();
	//dump_pools();
	//dump_task(&tasks[firsttask]);

	printf("init: switching to CPL/DPL=3\n");
	//print_mm(tasks[firsttask].pd);
	cr3_flush(tasks[firsttask].pd);
	printf("init: DONE\n");

	boot_done = true;

	gousermode(
			tasks[firsttask].tss.rip,
			tasks[firsttask].tss.cs,
			tasks[firsttask].tss.rflags,
			tasks[firsttask].tss.rsp,
			tasks[firsttask].tss.ss
			);
}
