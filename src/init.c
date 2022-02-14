#define _INIT_C
#include "klibc.h"
#include "mboot.h"
#include "acpi.h"
//#include "ppp.h"
//#include "slip.h"
#include "frame.h"
#include "file.h"
#include "mem.h"
#include "intr.h"
#include "page.h"
#include "dev.h"
#include "cpu.h"
#include "proc.h"
#include "pci.h"
#include "ram.h"
#include "ramfs.h"
#include "failfs.h"
#include "syscall.h"
#include "net.h"
#include "ip.h"

extern unsigned long firsttask, tick, task_lock, frames_lock;
extern volatile short *vga;
extern struct phys_mem_slot phys_mem_list[MAX_PHYS_MEM_SLOTS];
extern bool memdebug;
extern unsigned long high_mem_start, top_of_mem, free_page_size, total_frames;
extern unsigned long kernel_ds_end, nosched;
extern unsigned long *pagebm;
extern const struct task **taskbm;
extern pt_t *kernel_pd;
extern unsigned long mb_magic;
extern multiboot_info_t *mb_struct;
extern uint64_t num_kern_pools, pool_page_num;
extern bool mem_init;
extern struct mount *root;

extern void task1(void);
extern void sysenter(void);
extern noreturn void gousermode(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern void task2(void);
extern void syscall_init(void);

bool boot_done = false;


void setup_vga(void)
{
	vga = (short *)0xb8000;
	cls();
}

union {
	struct {
		unsigned icw4:1;
		unsigned single_pic:1;
		unsigned address_interval:1;
		unsigned level_triggered_int_mode:1;
		unsigned always1:1;
		unsigned isr_low:3;
	} __attribute__((packed));
	uint8_t a;
} PIC_ICW1;

union {
	struct {
		unsigned mode8086:1;
		unsigned auto_end_int:1;
		/* master+buf:
		 * 0?: nonbuffered
		 * 10: buffered slave
		 * 11: buffered master
		 */
		unsigned master:1;
		unsigned buf:1;
		unsigned special_nested_mode:1;
		unsigned zero:3;
	} __attribute__((packed));
	uint8_t a;
} PIC_ICW4;

/* ICW1 - Initialisation Command Word One 
 * ICW2 - Higher byte of ISR address (e.g. int 20 - 27)
 * ICW3 - Master Mode: bit denotes slave
 *      - Slave Mode:  bit 0-2 denote ID  
 * ICW4 - Initialisation Command Word Four
 */

#define PIC_ICW1_IC4	(1<<0)
#define PIC_ICW1_SNGL	(1<<1)
#define PIC_ICW1_ADI	(1<<2)
#define PIC_ICW1_LTIM	(1<<3)
#define PIC_ICW1_ALW1	(1<<4)

#define PIC_ICW4_MODE	(1<<0)
#define PIC_ICW4_AEOI	(1<<1)
#define PIC_ICW4_MS		(1<<2)

#define PICA_CMD	0x20
#define	PICA_DATA	0x21
#define	PICB_CMD	0xa0
#define	PICB_DATA	0xa1

static void setup_pic(void)
{
	outportb(PICA_CMD,  PIC_ICW1_ALW1|PIC_ICW1_IC4); /* ICW1: 0x11   */
	outportb(PICA_DATA, 0x20);          /* ICW2: 0x20 vector address */
	outportb(PICA_DATA, 0x04);          /* ICW3: 0x04 IRQ2 = PICB?   */
	outportb(PICA_DATA, PIC_ICW4_MODE); /* ICW4: 0x01                */
	outportb(PICA_DATA, 0x00);          /* OCW1: 0x00 unmask all IR  */

	outportb(PICB_CMD,  PIC_ICW1_ALW1|PIC_ICW1_IC4); /* ICW1: 0x11   */
	outportb(PICB_DATA, 0x28);          /* ICW2: 0x28 vector address */
	outportb(PICB_DATA, 0x02);          /* ICW3: slave ID #1         */
	outportb(PICB_DATA, PIC_ICW4_MODE); /* ICW4: 0x01                */
	outportb(PICB_DATA, 0x00);          /* OCW1: 0x00 unmask all IR  */
}

/*
uint64_t crap_gdt[] = {
	0x0,
	0x008f9a000000ffff,
	0x00af9a000000ffff,
	0x00cf92000000ffff,
	0x00cffe000000ffff,
	0x00cff2000000ffff,
	0x00cff2000000ffff,
	0x00CF9a000000ffff
};
*/

static inline void setup_gdt(void)
{
	unsigned long tss_p;

	gdtp.limit = (uint16_t)(sizeof(gdt) - 1);
	gdtp.base = (unsigned long)&gdt;
	tss_p = (unsigned long)(&global_tss);

	memset((char *)&gdt, 0, sizeof(gdt));

	//gdt_set_gate(_NULL_CS	,0,0,0,0,0); /* 0x0 */

	/* do not change the order of these without looking at IA32_STAR in setup_msr */

	gdt_set_gate64(_KERNEL_CS , 0     , -1                 , 0x0 , GTF_P                   , GDT_TYPE_CS64);        /* 0x08 */
	gdt_set_gate64(_KERNEL_DS , 0     , -1                 , 0x0 , GTF_W|GTF_P             , GDT_TYPE_DS64);        /* 0x10 */

	gdt_set_gate32(_USER32_CS , 0     , -1                 , 0x3 , GTF_R|GTF_P|GTF_D|GTF_G , GDT_TYPE_CS32);        /* 0x18 */
	gdt_set_gate32(_USER32_DS , 0     , -1                 , 0x3 , GTF_W|GTF_P|GTF_B|GTF_G , GDT_TYPE_DS32);        /* 0x20 */

	gdt_set_gate64(_USER_CS   , 0     , -1                 , 0x3 , GTF_P                   , GDT_TYPE_CS64);        /* 0x28 */
	gdt_set_gate64(_USER_DS   , 0     , -1                 , 0x3 , GTF_W|GTF_P             , GDT_TYPE_DS64);        /* 0x30 */

	gdt_set_gate64(_TSS_CS    , tss_p , sizeof(global_tss) , 0x0 , GTF_P                   , GDT_TYPE_TSSAVAIL64);
	gdt_flush();
}

//extern void int_0x20 (void *frame);

static inline void setup_ldt(void)
{
	idtp.limit = (uint16_t)(sizeof(idt)-1);
	idtp.base = (unsigned long)&idt;

	memset((char *)&idt, 0, sizeof(idt));

	idt_set_gate64(0x00, (unsigned long)_isr0,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x01, (unsigned long)_isr1,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x02, (unsigned long)_isr2,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x03, (unsigned long)_isr3,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x04, (unsigned long)_isr4,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x05, (unsigned long)_isr5,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x06, (unsigned long)_isr6,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x07, (unsigned long)_isr7,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x08, (unsigned long)_isr8,  _KERNEL_CS, 0, 1, GDT_TYPE_TRAP64);
	idt_set_gate64(0x09, (unsigned long)_isr9,  _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x0a, (unsigned long)_isr10, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x0b, (unsigned long)_isr11, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x0c, (unsigned long)_isr12, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x0d, (unsigned long)_isr13, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x0e, (unsigned long)_isr14, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x0f, (unsigned long)_isr15, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x10, (unsigned long)_isr16, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x11, (unsigned long)_isr17, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x12, (unsigned long)_isr18, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x13, (unsigned long)_isr19, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x14, (unsigned long)_isr20, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x15, (unsigned long)_isr21, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x16, (unsigned long)_isr22, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x17, (unsigned long)_isr23, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x18, (unsigned long)_isr24, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x19, (unsigned long)_isr25, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x1a, (unsigned long)_isr26, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x1b, (unsigned long)_isr27, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x1c, (unsigned long)_isr28, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x1d, (unsigned long)_isr29, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x1e, (unsigned long)_isr30, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);
	idt_set_gate64(0x1f, (unsigned long)_isr31, _KERNEL_CS, 0, 0, GDT_TYPE_TRAP64);

	idt_set_gate64(0x20, (unsigned long)_isr32, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x21, (unsigned long)_isr33, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x22, (unsigned long)_isr34, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x23, (unsigned long)_isr35, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x24, (unsigned long)_isr36, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x25, (unsigned long)_isr37, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x26, (unsigned long)_isr38, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x27, (unsigned long)_isr39, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x28, (unsigned long)_isr40, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x29, (unsigned long)_isr41, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x2a, (unsigned long)_isr42, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x2b, (unsigned long)_isr43, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x2c, (unsigned long)_isr44, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x2d, (unsigned long)_isr45, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x2e, (unsigned long)_isr46, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);
	idt_set_gate64(0x2f, (unsigned long)_isr47, _KERNEL_CS, 0, 0, GDT_TYPE_INT64);

	//	idt_set_gate(0x80, (unsigned long)int80_t_handler, _KERNEL_CS, 0xf, 0);

	idt_flush();
}


// FIXME

uint8_t	kernel_stack[STACK_SIZE*2];

static inline void setup_tss(void)
{
	memset((char *)&global_tss, 0, sizeof(global_tss));
	tss_flush(_TSS_CS);
}

static const char *const mb_mem_types[] = {
	"*UNDEFINED* ",
	"AVAILABLE   ",
	"RESERVED    ",
	"ACPI RECLAIM",
	"NVS         ",
	"BADRAM      ",
	NULL
};

static const int mb_mem_types_size = sizeof(mb_mem_types) / sizeof(mb_mem_types[0]);

__attribute__((nonnull)) static void setup_mem(const unsigned long magic, const multiboot_info_t *restrict const mbi)
{
	uint64_t i=0,j=0;
	unsigned long tmp;
	struct phys_mem_slot *pm = NULL;
	mem_init = false;

	set_cr0(get_cr0() & ~CR0_EM); // clear CR0.EM
	set_cr0(get_cr0() |  CR0_MP); // set   CR0.MP

	set_cr4(get_cr4() | CR4_OSFXSR);     // set   CR4.OSFXSR
	set_cr4(get_cr4() | CR4_OSXMMEXCPT); // set   CR4.OSXMMEXCPT

	if( magic != MULTIBOOT_BOOTLOADER_MAGIC ) {
		printf("PANIC: bad magic: %lx\n", magic);
		while(true) hlt(); 
	}
	printf("MB: flags=%0x\n", mbi->flags);

	if(mbi->flags & MULTIBOOT_INFO_MEMORY)
		printf( "MB: low mem:   %0lx\n"
				"MB: upper mem: %0lx\n",
				(uint64_t)mbi->mem_lower * 1024,
				(uint64_t)mbi->mem_upper * 1024);
	
	if(mbi->flags & MULTIBOOT_INFO_BOOTDEV)
		printf("MB: boot_device=%0x [drive=%x, part1=%x, part2=%x, part3=%x]\n", 
				mbi->boot_device,
				(mbi->boot_device >> 24) & 0xff,
				(mbi->boot_device >> 16) & 0xff,
				(mbi->boot_device >> 8) & 0xff,
				(mbi->boot_device) & 0xff
				);

	if(mbi->flags & MULTIBOOT_INFO_CMDLINE)
		printf("MB: cmd_line=%s\n", (char *)((uint64_t)mbi->cmdline));

	if(mbi->flags & MULTIBOOT_INFO_CONFIG_TABLE)
		printf("MB: config_table=%0x\n", mbi->config_table);
	
	if(mbi->flags & MULTIBOOT_INFO_DRIVE_INFO)
		printf("MB: drives=%0x[%x]\n", mbi->drives_addr, mbi->drives_length);

	if(mbi->flags & MULTIBOOT_INFO_BOOT_LOADER_NAME)
		printf("MB: name=%s\n", (char *)(uint64_t)mbi->boot_loader_name);

	if(mbi->flags & MULTIBOOT_INFO_APM_TABLE)
		printf("MB: apm_table=%0x\n", mbi->apm_table);

	if(mbi->flags & MULTIBOOT_INFO_MEM_MAP) {
		memory_map_t *mm;
		for( mm = (memory_map_t *)(uint64_t)mbi->mmap_addr;
				(unsigned long)mm < mbi->mmap_addr + mbi->mmap_length;
				mm = (memory_map_t *)((unsigned long)mm + mm->size + 
					sizeof(mm->size)) )
		{
			uint64_t base = mm->base_addr_high;
			base <<= 32;
			base |= mm->base_addr_low;

			uint64_t len = mm->length_high;
			len <<= 32;
			len |= mm->length_low;

			printf("MM:\t%0lx - %0lx\t(%0lx)\t[%s]\n",
					base,
					base + len,
					len,
					mm->type < mb_mem_types_size ? mb_mem_types[mm->type] : "UNKNOWN");

			if( mm->type == MULTIBOOT_MEMORY_AVAILABLE )
				add_to_useable_mem((void *)base, len);
		}

	} else {
		printf("PANIC: no memory map!: %x\n", mbi->mmap_addr);
		while(true) hlt();
	}

	i = 0;
	pm = (struct phys_mem_slot *)&phys_mem_list[i];

	while( pm->len )
	{
		printf("RAM: phys: %0lx to %0lx\n", (uint64_t)pm->from, (uint64_t)pm->to);

		if(pm->from < &end_of_kernel && pm->to > &end_of_kernel) { 
			high_mem_start = (uint64_t)&end_of_kernel; 
		}

		if((uint64_t)pm->to > top_of_mem)
			top_of_mem = (uint64_t)pm->to;

		pm = &phys_mem_list[++i];

		if (i >= MAX_PHYS_MEM_SLOTS ) {
			printf("PANIC: too many physical memory slots\n");
			while(1) hlt();
		}
	}

	high_mem_start  += (high_mem_start + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
	kernel_ds_end    = high_mem_start;
	free_page_size   = (total_frames   = top_of_mem/PAGE_SIZE) / (sizeof(uint64_t)*8);

	printf("RAM: high_mem_start: %0lx\n", high_mem_start);
	printf("RAM: top_of_mem:     %0lx\n", top_of_mem);

	printf("RAM: free_page_size: %0lx\n", free_page_size);
	printf("RAM: total_frames:   %0lx\n", total_frames);
	printf("RAM: end_of_kernel:  %0lx\n", (uint64_t)&end_of_kernel);

	taskbm = NULL;
	pagebm = NULL;
	num_kern_pools = 0;

    /* set-up the kernel page descriptor table */
	if((kernel_pd = kmalloc_align(sizeof(pt_t),"kernel_pd",NULL,KMF_ZERO)) == NULL) {
		printf("PANIC: failed to allocate kernel_pd\n");
		while(true) hlt(); 
	} 

	printf("RAM: kernel_pd created at 0x%p len 0x%lx\n", 
			(void *)kernel_pd, 
			sizeof(pt_t));

	for(j = 0; j <= top_of_mem; j += PGSIZE_1G)
		if(!create_page_entry_1g(kernel_pd, j, j, PEF_P|PEF_W|PEF_G, NULL)) {
			printf("PANIC: unable to map 1g pages\n");
			while(1) hlt();
		}

	set_cr3(kernel_pd);
	printf("RAM: kernel_pd installed\n");

    /* setup the frame allocation bitmap */
	const uint64_t pagebm_len = free_page_size * sizeof(uint64_t);

	if((pagebm = (unsigned long *) kmalloc(pagebm_len, "pagebm", NULL, KMF_ZERO)) == NULL) {
		printf("PANIC: failed to allocate pagebm\n");
		while(true) hlt();
	}

	printf("RAM: pagebm at 0x%p with 0x%lx entries using 0x%lx bytes\n", 
			(void *)pagebm, free_page_size, pagebm_len);

    /* setup the task to frame allocation */
	const uint64_t taskbm_len = total_frames * sizeof(struct task *);

	taskbm = (const struct task **) kmalloc(taskbm_len, "taskbm",NULL,0);
	if(!taskbm) {
		printf("PANIC: failed to allocate taskbm\n");
		while(true) hlt();
	}

	memset((char *)taskbm, -1, taskbm_len);
	printf("RAM: taskbm at 0x%p with 0x%lx entries using 0x%lx bytes\n", 
			(void *)taskbm, 
			total_frames, 
			taskbm_len);

    /* mark from 0 to the end of init memory as allocate frames */
	tmp = taskbm ? (uint64_t)(taskbm + taskbm_len) : (uint64_t)(pagebm + pagebm_len);

	for(i = 0; i < top_of_mem; i += PAGE_SIZE)
		if(!is_useable((void *)i) || i <= tmp )
			set_frame((void *)i);

    /* repare the kernel memory allocator */
	memset(&kern_pool, 0, sizeof(kern_pool));

	printf("RAM: kern_pool cleared\n");
	pool_page_num = 16;

    /* initialise the kernel memory pools */
	for(i=0;i<KERN_POOLS;i++)
		do_one_pool(NULL);

	mem_init = true;
	printf("RAM: mem_init = true\n");
}

#define PIT_CH0 0x40
#define PIT_CH1 0x41
#define PIT_CH2 0x42
#define PIT_CMD 0x43

#define PIT_MODE_CH0	(0x00)
#define PIT_MODE_CH1	(0x40)
#define PIT_MODE_CH2	(0x80)
#define PIT_MODE_READ	(0xc0)

#define PIT_MODE_LATCH  (0x00)
#define PIT_MODE_LO		(0x10)
#define PIT_MODE_HI		(0x20)
#define PIT_MODE_LOHI	(0x30)

#define PIT_OP_M0		(0x00)
#define PIT_OP_M1		(0x02)
#define PIT_OP_M2		(0x04)
#define PIT_OP_M3		(0x06)
#define PIT_OP_M4		(0x08)
#define PIT_OP_M5		(0x0a)
#define PIT_OP_M2B		(0x0c)
#define PIT_OP_M3B		(0x0e)

#define PIT_BCD			(0x1)
#define PIT_BINARY		(0x0)

static void setup_pit(const uint32_t freq)
{
	// 1.193182 MHz

	const uint32_t req = (1193180 / freq);
	const unsigned char l = (unsigned char)(req & 0xff);
	const unsigned char h = (unsigned char)((req>>8) & 0xff);

	// PIT_BINARY|PIT_OP_M2|PIT_MODE_LOHI

	outportb(0x43, (unsigned char)0x36);

	outportb(0x40, l);
	outportb(0x40, h);
}

static void setup_serial(const uint16_t port, const uint32_t speed)
{
	const uint32_t div = 115200/speed;

	outportb(port+SER_INTEN,	0x00);						// turn interupts off
	outportb(port+SER_LCR,		SER_LCR_DLAB);				// enable DLAB
	outportb(port+SER_LSB_DIV,	(uint8_t)(div & 0xff));		// lo byte 115200
	outportb(port+SER_MSB_DIV,	(uint8_t)(div>>8));			// high byte
	outportb(port+SER_LCR,		SER_LCR_8|SER_LCR_NOP);		// 8n1, disable DLAB
	outportb(port+SER_FCR,		SER_FCR_ENABLE|SER_FCR_CLR_RX|SER_FCR_CLR_TX|SER_FCR_14B);		
	
	// irq on
	outportb(port+SER_MCR,		SER_MCR_AUX2|SER_MCR_DTR|SER_MCR_RTS);
	outportb(port+SER_INTEN,	0x01);						// turn interrupts on

	//	printf("ser: port %x set to %d\n", port, speed);
	
}

//extern uint64_t task1_end,task2_end;

static const unsigned char idle_task_code[] = {
	0xF4, // HLT
	0xE9, 0xFA, 0xFF, 0xFF, 0xFF // JMP
};


//#define KERN_MEM	(64ULL*0x1000000ULL)

static void create_tasks(bool has_root)
{
	uint8_t *tmp,*tmp2;
	uint64_t vaddr, offset, daddr;
	uint8_t *code, *data;
	uint64_t clen, dlen;
	pt_t *idle_pd = NULL, *pd = NULL;
	struct task *idle_task, *init_task;

	memset(tasks, 0, sizeof(struct task) * NUM_TASKS);

	/* set-up idle task */
	idle_task = &tasks[0];

	if((idle_pd = kmalloc_align(sizeof(pt_t),"idle.pml4", idle_task, KMF_ZERO)) == NULL) {
		printf("PANIC: cannot kmalloc idle task pd\n");
		while(1) hlt();
	}

	/* idle task runs in kernel mode so is special and doesn't have user pt*/
	clone_mm(kernel_pd, idle_pd, idle_task, false);

	idle_task->pd = idle_pd;

	/*
	for(offset = 0; offset < KERN_MEM; offset += PGSIZE_1G)
		if(!create_page_entry_1g(idle_pd,offset,offset,PEF_W|PEF_P|PEF_G, &tasks[0])) {
			printf("PANIC: cannot alloc kern pages for idle task\n");
			while(1) hlt();
		}
		*/

	if((tmp = find_frame(&tasks[0])) == NULL) {
		printf("PANIC: no pages for idle task\n");
		while(1) hlt();
	}

	memcpy(tmp, &idle_task_code, sizeof(idle_task_code)); 
	if((tmp2 = find_frame(idle_task)) == NULL) {
		printf("PANIC: no pages for whatever this is\n");
		while(1) hlt();
	}

	setup_task(idle_task, (uint64_t)tmp, KERNEL_TASK, idle_pd, "idle", (uint64_t)tmp2, 0);
	idle_task->state = STATE_RUNNING;

	if(!has_root)
		return;

	/* Set up init task */
	init_task = &tasks[1];

	if((pd = kmalloc_align(sizeof(pt_t),"task1.pml4", init_task,KMF_ZERO)) == NULL) {
		printf("PANIC: cannot kmalloc task1 pd\n");
		while(1) hlt();
	}
	clone_mm(kernel_pd, pd, init_task, false);

	code = data = NULL;
	clen = dlen = 0;
	vaddr = 0;

	init_task->pd = pd;

	/*
	for(offset = 0; offset < KERN_MEM; offset += PGSIZE_1G)
		if(!create_page_entry_1g(pd, offset, offset, PEF_P|PEF_G|PEF_W, init_task)) {
			printf("PANIC: cannot create page for task1\n");
			while(1) hlt();
		}*/

	//printf("create_tasks: calling do_exec for tasks[1] ");
	if(do_exec(init_task, "/init", &code, &clen, &data, &dlen, &vaddr, &daddr) == -1) {
		printf("PANIC: do_exec failed\n");
		while(1) hlt();
	}
	//printf("done\n");
	//printf("create_tasks: /init : code=%p[%lx], data=%p[%lx], vaddr=%lx\n", (void *)code, clen, (void *)data, dlen, vaddr);

	init_task->code_start = (uint8_t *)vaddr;
	init_task->code_end = (uint8_t *)vaddr + clen;
	init_task->data_start = (uint8_t *)daddr;
	init_task->data_end = (uint8_t *)daddr + dlen;
	init_task->stack_end = (uint8_t *)0xc0000000UL;
	init_task->stack_start = (uint8_t *)((uint64_t)init_task->stack_end - STACK_SIZE);
	init_task->heap_end = init_task->heap_start = (init_task->data_end == NULL ? init_task->code_end : 
			init_task->data_end);

	for(offset = 0; offset < STACK_SIZE; offset += PGSIZE_4K) {
		tmp = (void *)find_frame(init_task);
		if(!tmp || !create_page_entry_4k(pd, offset + (uint64_t)init_task->stack_start, 
					(uint64_t)tmp, PEF_P|PEF_U|PEF_W, init_task)) {
			printf("PANIC: cannot alloc page for task1\n");
			while(1) hlt();
		}
	}

	setup_task(init_task, vaddr, USER_TASK, pd, "/init", (uint64_t)init_task->stack_end - 8, 1);

	/* Set up the other idle task */
	init_task = &tasks[2];

	if((pd = kmalloc_align(sizeof(pt_t),"task2.pml4", init_task,KMF_ZERO)) == NULL) {
		printf("PANIC cannot kmalloc task2 pd\n");
		while(1) hlt();
	}
	clone_mm(kernel_pd, pd, init_task, false);

	code = data = NULL;
	clen = dlen = 0;
	vaddr = 0;

	init_task->pd = pd;

	/*
	for(offset = 0; offset < KERN_MEM; offset += PGSIZE_1G)
		if(!create_page_entry_1g(pd, offset, offset, PEF_P|PEF_G|PEF_W, init_task)) {
			printf("PANIC: cannot create page for task2\n");
			while(1) hlt();
		}*/

	//printf("create_tasks: calling do_exec for tasks[2] ");
	if(do_exec(init_task, "/init", &code, &clen, &data, &dlen, &vaddr, &daddr) == -1) {
		printf("PANIC: do_exec failed\n");
		while(1) hlt();
	}
	//printf("done\n");

	//printf("create_tasks: /init : code=%p[%lx], data=%p[%lx], vaddr=%lx\n", (void *)code, clen, (void *)data, dlen, vaddr);

	init_task->code_start = (uint8_t *)vaddr;
	init_task->code_end = (uint8_t *)vaddr + clen;
	init_task->data_start = (uint8_t *)daddr;
	init_task->data_end = (uint8_t *)daddr + dlen;
	init_task->stack_end = (uint8_t *)0xc0000000UL;
	init_task->stack_start = (uint8_t *)((uint64_t)init_task->stack_end - STACK_SIZE);
	init_task->heap_end = init_task->heap_start = (init_task->data_end == NULL ? init_task->code_end : 
			init_task->data_end);

	for(offset = 0; offset < STACK_SIZE; offset += PGSIZE_4K) {
		tmp = (void *)find_frame(init_task);
		if(!tmp || !create_page_entry_4k(pd, offset + (uint64_t)init_task->stack_start, 
					(uint64_t)tmp, PEF_P|PEF_U|PEF_W, init_task)) {
			printf("PANIC: cannot alloc page for task2\n");
			while(1) hlt();
		}
	}

	setup_task(init_task, vaddr, USER_TASK, pd, "/init.2", (uint64_t)init_task->stack_end - 8, 2);
}


/*
 * IA32_FMASK:
 * 63-32:	Reserved
 * 31-00:	SYSCALL EFLAGS Mask
 *
 * IA32_LSTAR:
 * 63-00:	Target RIP
 *
 * IA32_STAR
 * 63-48:	SYSRET	CS and SS
 *			64-bit: CS is selector + 16
 *			64-bit: SS is selector + 8
 *			32-bit: CS is selector + 0
 *			32-bit: SS is selector + 8
 * 47-32:	SYSCALL	CS and SS
 * 31-00:	Reserved
 */

static inline void setup_msr(void)
{
	STAR star;

	star.a.syscall_eip = 0x800b135;
	star.a.syscall_csss = _KERNEL_CS|CPL_0;
	star.a.sysret_csss = _USER32_CS|CPL_3;

	write_msr(MSR_LSTAR, (uint64_t)sysenter);	
	write_msr(MSR_STAR, star.b);

	// disable interrupts, traps and cld
	write_msr(MSR_SFMASK, F_IF|F_DF|F_TF);
}


#define	_cpuid(func,ax,bx,cx,dx) \
	__asm__ volatile("cpuid":"=a"(ax),"=b"(bx),"=c"(cx),"=d"(dx):"a"(func));

#define CPUID_1GBPG	0x04000000

__attribute__((nonnull)) static void init_lapic(volatile struct lapic *l)
{
	printf("lapic: address:%p\n", (void *)l);
	printf("lapic: ver:%x\n", l->ver_reg & 0xff);
}

static void cpu_init(void)
{
	uint32_t ret[4];
	unsigned char id[13];
	struct cpu *cpu = &cpus[0];
	APICbar ab;

	_cpuid(0x0, ret[0], ret[1], ret[2], ret[3]);

	memcpy(&id[0], &ret[1], 4);
	memcpy(&id[4], &ret[3], 4);
	memcpy(&id[8], &ret[2], 4);
	id[12] = '\0';

	printf("cpu_init: cpu[0]: \"%s\" max:0x%x\n", id, ret[0]);

	const uint32_t max = ret[0];
	const uint32_t platform_info = read_msr(MSR_PLATFORM_INFO);

	printf("cpu_init: platform_info:%x\n", platform_info);

	if(max >= 0x15) {
		_cpuid(0x15, ret[0], ret[1], ret[2], ret[3]);
		printf("cpu0: TSC: %x %x %x %x\n",
				ret[0], ret[1], ret[2], ret[3]);
	}

	ab.b = read_msr(MSR_APIC_BASE);
	printf("cpu0: MSR_APIC_BAR: cpu_is_bsp?:%x, apic_enable:%x, ", 
			ab.processor_is_bsp, ab.apic_enable);
	printf("apic_base:%lx\n", APIC_BASE(ab));
	create_page_entry_4k(kernel_pd, APIC_BASE(ab), APIC_BASE(ab), PEF_P|PEF_W|PEF_G, NULL);
	cpu->lapic = (volatile struct lapic *)APIC_BASE(ab);

	ab.apic_enable = 1;
	write_msr(MSR_APIC_BASE, ab.b);

	init_lapic(cpu->lapic);

	_cpuid(0x1, ret[0], ret[1], ret[2], ret[3]);
	num_cpus = ((ret[1] & 0x00ff0000)>>16);
	if(!num_cpus) num_cpus++;
	printf("cpu0: CPU Count:%x\n",num_cpus); 
	printf("cpu0: ");
	printf("stp:%x,", (cpu->stepping = (ret[0] & 0x0000000f)));
	printf("mod:%x,", (cpu->model = (((ret[0] & 0x000000f0)>>4)|
					((ret[0] & 0x000f0000)>>16))));
	printf("fam:%x,", (cpu->family = ((((ret[0] & 0x00000f00)>>8)|
						((ret[0] & 0x00f00000)>>20)))));
	printf("id:%x,", (cpu->apic_id = ((ret[1] & 0xff000000)>>24)));
	printf("APIC:%x\n", ((ret[3] & (1<<9)))?1:0);

	_cpuid(0x80000001, ret[0], ret[1], ret[2], ret[3]);
}

static inline void pci_init(void)
{
	unsigned int i,j,z;
	uint32_t vend, dev;
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

						if((ndev = add_pci_device(z,i,j)) == NULL)
							printf("pci_init: failed to add %d:%d:%d\n", z, i, j);
					}
				}
			}
		}
	}
	printf("pci_init: probing complete\n");
}

static inline void dev_init(void)
{
	//uint64_t i;

	printf("dev_init: ");
	add_dev(DEV_ID(CON_MAJOR,CON_MINOR), DEV_CHAR, 
			&console_char_ops, "con", NULL);
	printf("con ");
	for(int i=0;i<NUM_RD;i++) 
	{
		add_dev(DEV_ID(RD_MAJOR,RD_0_MINOR+i), DEV_BLOCK, 
				&ram_block_ops, "ram", NULL);
		printf("ram(%x) ", i);
	}
	add_dev(DEV_ID(SER_MAJOR,SER_0_MINOR), DEV_CHAR,
			&serial_char_ops, "ser", NULL);
	printf("ser(0) ");
	printf("\n");
}

static inline void proto_init(void)
{
	printf("proto_init: ");
	add_dev(NETPROTO_IP, DEV_PROTO, &ip_proto_ops, "ip", NULL);
	printf("ip ");
	printf("\n");
}

static void net_init(void)
{
	//return;

	printf("net_init: ");
	//	add_dev(NETDEV_PPP, DEV_NET, &ppp_net_ops, "ppp");
	//	printf("ppp ");
	//	add_dev(NETDEV_SLIP, DEV_NET, &slip_net_ops, "slip");
	//	printf("slip ");
	printf("\n");
}

static void fs_init(void)
{
	printf("fs_init: ");
	add_dev(0, DEV_FS, &ramfs_ops, "ramfs", NULL);
	printf("ramfs ");
	printf("\n");
}

__attribute__((nonnull)) void kernmain(const unsigned long magic, const multiboot_info_t *const restrict mbd)
{
	//int i;
	//struct net_dev *nd;
	//struct char_dev *cd;
	//struct net_proto *np;

	//memdebug = true;

	nosched = tick = curtask = 0;
	firsttask = 1;
	devs = NULL;
	//	netdevs = NULL;

	//setup_vga();
	setup_serial(COM1, 115200);
	//setup_serial(COM2, 115200);
	printf("FailOS\n");
	setup_mem(magic, mbd);
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

	cpu_init();
	acpi_probe();
	proto_init();
	pci_init();
	file_init();
	dev_init();
	fs_init();
	net_init();
	syscall_init();

	root_mnt = NULL;
	root_fsent = NULL;

	struct block_dev *hd;
	if((hd = find_dev(DEV_ID(RD_MAJOR, RD_0_MINOR), DEV_BLOCK)) == NULL) {
		printf("init: unable to find root device (%d,%d)\n", RD_MAJOR, RD_0_MINOR);
		goto no_root;
	}

	if((root_mnt = do_mount(hd, NULL, &ramfs_ops)) == NULL) {
		printf("init: unable to mount %s filesystem on /\n", ramfs_ops.name);
		goto no_root;
	}
	
	root_fsent = root_mnt->root;
	struct fileh *fh1, *fh2;

	hd = find_dev(DEV_ID(IDE_MAJOR, 0), DEV_BLOCK);
	if(hd) {
		struct mount *fail_mnt;
		int rc;

//		dump_fsents();
		printf("\n\ntrying to mount /mnt\n\n");
		if((fail_mnt = do_mount(hd, resolve_file("/mnt", root_fsent, &rc), &failfs_ops)) == NULL)
			goto no_root;
//		dump_fsents();
//		printf("\n\n");
//		while(1) hlt();


		if((fh1 = do_open("/mnt/newfile.txt", NULL, O_CREAT|O_RDWR, 0755, &rc)) == NULL)
			printf("init: can't open file: %d: %s\n", rc, strerror(rc));
//		dump_fsents();
//		printf("\n\n");

		if((fh2 = do_open("/mnt/newfile2.txt", NULL, O_CREAT|O_RDWR, 0755, &rc)) == NULL)
			printf("init: can't open file: %d: %s\n", rc, strerror(rc));
//		dump_fsents();
//		printf("\n\n");

		if((do_mkdir(NULL, "/mnt/tmp", 0755)) < 0)
			printf("init: can't mkdir: %d: %s\n", rc, strerror(rc));
//		dump_fsents();
//		printf("\n\n");

		if((do_mkdir(NULL, "/mnt/tmp2", 0755)) < 0)
			printf("init: can't mkdir: %d: %s\n", rc, strerror(rc));
//		printf("\n\n");

//		dump_fsents();
//		printf("\n\n");
//		while(1) hlt();

	} else
		printf("init: unable to mount root (no device)\n");

	//nd = find_dev(NETDEV_SLIP, DEV_NET);
	//cd = find_dev(DEV_ID(SER_MAJOR, SER_0_MINOR), DEV_CHAR);
	//np = find_dev(NETPROTO_IP, DEV_PROTO);
	//init_netdev(nd, cd, DEV_CHAR, np);

no_root:
//	while(1) hlt();
	create_tasks((root_mnt != NULL));
	curtask = firsttask = root_mnt == NULL ? 0 : 1;

	kscan();

	/* enable rd/wr fs/gs base instructions for usermode */
	//set_cr4(get_cr4()|(1<<16));

	write_msr(MSR_KERNEL_GSBASE, (uint64_t)&tasks[firsttask]);
	write_msr(MSR_GSBASE, 0x0);

	global_tss.rsp0 = (uint64_t)tasks[firsttask].kernelsptr;
	global_tss.ist1 = (uint64_t)kmalloc_align(STACK_SIZE, "#DF stack", NULL,KMF_ZERO);

	tasks[firsttask].state = STATE_RUNNING;
	set_cr3(tasks[firsttask].pd);

	if(root_mnt)
		for(int i = 1; i <= 2; i++) {
			if( (tasks[i].fps[0] = do_open("/dev/tty", &tasks[i], O_RDONLY, 0, NULL)) == NULL )
				printf("init: unable to open stdin\n");
			if( (tasks[i].fps[1] = do_open("/dev/tty", &tasks[i], O_WRONLY, 0, NULL)) == NULL )
				printf("init: unable to open stdout\n");
			if( (tasks[i].fps[2] = do_open("/dev/tty", &tasks[i], O_WRONLY, 0, NULL)) == NULL )
				printf("init: unable to open stderr\n");
		}

//	dump_fsents();
	do_close(fh1, NULL);
	do_close(fh2, NULL);
	flush_fsents();
//	dump_fsents();
//	while(1) hlt();
	printf("init: DONE\n");
	boot_done = true;

	/* printf("init: gousermode rip=%lx cs=%lx rflags=%lx rsp=%lx ss=%lx\n", tasks[firsttask].tss.rip, tasks[firsttask].tss.cs, tasks[firsttask].tss.rflags, tasks[firsttask].tss.rsp, tasks[firsttask].tss.ss); */

	printf("init: switching to CPL3 and PID %lx\n", firsttask);
	gousermode(
			tasks[firsttask].tss.rip,
			tasks[firsttask].tss.cs,
			tasks[firsttask].tss.rflags,
			tasks[firsttask].tss.rsp,
			tasks[firsttask].tss.ss
			);
}
