#define _INIT_C
#include <klibc.h>
#include <mboot.h>
#ifdef WANT_ACPI
# include <acpi.h>
#endif
#include <frame.h>
#include <file.h>
#include <mem.h>
#include <intr.h>
#include <page.h>
#include <dev.h>
#include <cpu.h>
#include <proc.h>
#ifdef WANT_PCI
# include <pci.h>
#endif
#ifdef WANT_RAMDISK
# include <ram.h>
#endif
#ifdef WANT_RAMFS
# include <ramfs.h>
#endif
#ifdef WANT_FAILFS
# include <failfs.h>
#endif
#include <syscall.h>
#ifdef WANT_NET
# include <net.h>
# ifdef WANT_IP
#  include <ip.h>
# endif
#endif
#include <pit.h>
#include <pic.h>

extern unsigned long mb_magic;
extern multiboot_info_t *mb_struct;


/* script.ld */
extern uintptr_t phys_text;
extern uintptr_t mcode, mdata_end;
extern uintptr_t virt_text;
extern uintptr_t code, kernel_start, code_end;
extern uintptr_t data, data_end;
extern uintptr_t data_ro, data_ro_end;
extern uintptr_t bss, bss_end;
extern uintptr_t kernel_final;
extern uintptr_t kernel_phys_end;

extern void task1(void);
extern void task2(void);

bool boot_done = false;
uintptr_t kern_heap_top;
uintptr_t kern_mem_start, kern_mem_end;

#ifdef WANT_VGA
void setup_vga(void)
{
	vga = (void *)(uintptr_t)0xb8000UL;
	cls();
}
#endif

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

static void setup_gdt(void)
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

static void setup_ldt(void)
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

static void setup_tss(void)
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

static const unsigned int mb_mem_types_size = sizeof(mb_mem_types) / sizeof(mb_mem_types[0]);

__attribute__((nonnull))
static void setup_mem(const unsigned long magic, const multiboot_info_t *const mbi)
{
	uint64_t i=0;//,j=0;
	unsigned long tmp;
	struct phys_mem_slot *pm = NULL;
	mem_init = false;

	/* mboot.S has set:
	 * CR4.PAE=1
	 * IA32_EFER.LME=1 "IA-32e mode"
	 *
	 * Therefore we operating with "4-level paging":
	 *
	 * CR0.PG=1, CR4.PAE=1, IA32_EFER.LME=1, CR4.LA57=0
	 * Linear addr width:      48b
	 * Physical addr width: <= 52b
	 * Page sizes: 4KiB/2MiB/1GiB
	 * NX is supported (if IA32_EFER.NXE=1)
	 * PCIDs and protection keys are supported
	 *
	 * Other flags:
	 *
	 * CR0.WP =0	Supervisor can write anything it can read
	 * CR4.PGE=1	Enable global pages
	 * CR4.SMEP=1	Prevent supervisor executing user pages
	 *
	 * in 4-level paging: heac paging structure composes 512 (2**9) entries
	 *
	 * PML4 table is located in phys CR3. PS must be 0. It contains PML4Es
	 * PDPT is located at PML4E. PS=1 means 1-GByte page else contains PDPTE
	 * PD is located at PDPTE. PS=1 means 2-MByte page else contains PDE
	 * PT is located at PDE. Contains PTE.
	 */

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
		printf( "MB: low mem:   0x%0lx\n"
				"MB: upper mem: 0x%0lx\n",
				(uint64_t)mbi->mem_lower * 1024,
				(uint64_t)mbi->mem_upper * 1024);
	
	if(mbi->flags & MULTIBOOT_INFO_BOOTDEV)
		printf("MB: boot_device=%0x [drive=%02x, part1=%02x, part2=%02x, part3=%02x]\n", 
				mbi->boot_device,
				(mbi->boot_device >> 24) & 0xff,
				(mbi->boot_device >> 16) & 0xff,
				(mbi->boot_device >> 8) & 0xff,
				(mbi->boot_device) & 0xff
				);

	if(mbi->flags & MULTIBOOT_INFO_CMDLINE)
		printf("MB: cmd_line=<%s>\n", (char *)((uint64_t)mbi->cmdline));

	if(mbi->flags & MULTIBOOT_INFO_CONFIG_TABLE)
		printf("MB: config_table=%0x\n", mbi->config_table);
	
	if(mbi->flags & MULTIBOOT_INFO_DRIVE_INFO)
		printf("MB: drives=%0x[%x]\n", mbi->drives_addr, mbi->drives_length);

	if(mbi->flags & MULTIBOOT_INFO_BOOT_LOADER_NAME)
		printf("MB: name=<%s>\n", (char *)(uint64_t)mbi->boot_loader_name);

	if(mbi->flags & MULTIBOOT_INFO_APM_TABLE)
		printf("MB: apm_table=%0x\n", mbi->apm_table);

	if(mbi->flags & MULTIBOOT_INFO_MEM_MAP) {
		memory_map_t *mm;
		for(    mm = (void *)(uintptr_t)mbi->mmap_addr;
				(uintptr_t)mm < (mbi->mmap_addr + mbi->mmap_length);
				mm = (void *)((uintptr_t)mm + mm->size + sizeof(mm->size)) 
				)
		{
			uintptr_t base = mm->base_addr_high;
			base <<= 32;
			base |= mm->base_addr_low;

			size_t len = mm->length_high;
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
	pm = &phys_mem_list[i];

	kern_mem_start = (uintptr_t)&kernel_final;// - 0xc0000000;
	kern_mem_end   = kern_mem_start;

	while( pm->len )
	{
		printf("RAM: phys: %0lx to %0lx\n", (uint64_t)pm->from, (uint64_t)pm->to);

		if((uint64_t)pm->to > top_of_mem)
			top_of_mem = (uint64_t)pm->to;

		pm = &phys_mem_list[++i];

		if (i >= MAX_PHYS_MEM_SLOTS ) {
			printf("PANIC: too many physical memory slots\n");
			while(1) hlt();
		}
	}

	pagebm_max  = (total_frames   = top_of_mem/PAGE_SIZE) / (sizeof(uint64_t)*8);

	printf("RAM: pagebm_max:      0x%lx\n", pagebm_max);
	printf("RAM: total_frames:    0x%lx\n", total_frames);

	printf("RAM: top_of_mem:      0x%lx\n", top_of_mem);

	printf("RAM: mcode:           0x%p\n", (void *)&mcode);
	printf("RAM: mdata_end:       0x%p\n", (void *)&mdata_end);
	printf("RAM: kernel_phys_end: 0x%p\n", (void *)&kernel_phys_end);
	printf("RAM: kernel_start:    0x%p\n", (void *)&kernel_start);
	printf("RAM: code:            0x%p\n", (void *)&code);
	printf("RAM: code_end:        0x%p\n", (void *)&code_end);
	printf("RAM: data:            0x%p\n", (void *)&data);
	printf("RAM: data_end:        0x%p\n", (void *)&data_end);
	printf("RAM: data_ro:         0x%p\n", (void *)&data_ro);
	printf("RAM: data_ro_end:     0x%p\n", (void *)&data_ro_end);
	printf("RAM: bss:             0x%p\n", (void *)&bss);
	printf("RAM: bss_end:         0x%p\n", (void *)&bss_end);
	printf("RAM: kernel_final:    0x%p\n", (void *)&kernel_final);

	//taskbm = NULL;
    lockbm = NULL;
	pagebm = NULL;
	num_kern_pools = 0;

	/* setup the frame allocation bitmap */
	const size_t pagebm_bytes = pagebm_max * sizeof(uint64_t);

	if((pagebm = (uint64_t *)kmalloc_align(pagebm_bytes, "pagebm", NULL, 2)) == NULL) {
		printf("PANIC: failed to allocate pagebm\n");
		while(true) hlt();
	}
	printf("RAM: pagebm at 0x%p with 0x%lx entries using 0x%lx bytes\n", 
			(void *)pagebm, pagebm_max, pagebm_bytes);
	memset(pagebm, 0, pagebm_bytes);
    pagebm_chksum = _check_pagebm_chksum(__FILE__,__func__,__LINE__);
	

	/* mark from 0 to the end of init memory as allocate frames */
	printf("RAM: marking unuseable frames\n");
	kern_mem_end = (kern_mem_end + (PGSIZE_4K-1)) & ~(PGSIZE_4K-1);
	printf("RAM: kern_mem_end:    0x%p\n", (void *)kern_mem_end);
	tmp = kern_mem_end - (uintptr_t)&virt_text;
	printf("RAM: kern_mem_end(py):0x%p\n", (void *)tmp);

	set_n_frames((void *)(uintptr_t)&mcode, (tmp - (uintptr_t)&mcode)/PAGE_SIZE);
    pagebm_chksum = calc_pagebm_chksum();
	set_n_frames(0, 0x100000/PAGE_SIZE);
    pagebm_chksum = calc_pagebm_chksum();

	for (uintptr_t ii = 0x100000; ii < top_of_mem; ii += PAGE_SIZE) {
		if( !is_useable((void *)ii) ) {
			set_frame((void *)ii);
		}
	}
    /* set-up the kernel page descriptor table */
	if ((kernel_pd = alloc_pd(NULL)) == NULL) {
		printf("PANIC: failed to allocate kernel_pd\n");
		while(true) hlt(); 
	} 
	printf("RAM: kernel_pd created at 0x%p len 0x%lx\n", (void *)kernel_pd, sizeof(pt_t));

#define KERN_PD_FRAMES 3
	/* PDPT, PD, PT (kernel_pd is PML4) */
    pt_t (*const frames)[KERN_PD_FRAMES] = find_n_frames(KERN_PD_FRAMES, 0, false);

    if (frames == NULL) {
        printf("PANIC: unable to find frames for kernel_pd\n");
        while(true) hlt();
    }
	memset(frames, 0, KERN_PD_FRAMES * PGSIZE_4K);

	pt_t *pdpt = &(*frames)[0];
	pt_t *pd0  = &(*frames)[1];
	pt_t *pd3  = &(*frames)[3];

	/* set the PML4E in the PML4, pointing to the PDPT */
	kernel_pd->table_u64[0] = (uintptr_t)pdpt;
	kernel_pd->table_pe[0].present = 1;

	/* set the 1st GiB PDPTE in the PDPT, for identity mapping */
	pdpt->table_u64[0] = (uintptr_t)pd0;
	pdpt->table_pe[0].present = 1;
	pdpt->table_pe[0].write   = 1;

	/* set the 4th GiB PDPTE, pointing to a PD, for kernel quarter */
	pdpt->table_u64[3] = (uintptr_t)pd3;
	pdpt->table_pe[3].present = 1;
	pdpt->table_pe[3].write   = 1;

	/* identity map the first 2MiB via a PDE in the PD, for use by CR3 */

    /* FIXME this is not right, it just moves the problem that find_frame eventually
     * gives a frame not identity mapped so CR3 related functions explode */
    for (int jj = 0; jj < (int)(PGSIZE_4K/sizeof(uint64_t)); jj++) {
        pd0->table_u64[jj] = (uint64_t)jj * PGSIZE_2M;
        pd0->table_pe[jj].present = 1;
        pd0->table_pe[jj].write   = 1;
        pd0->table_pe[jj].global  = 1;
        pd0->table_pe[jj].last    = 1;
    }

    int pages = (((kern_mem_end - (uintptr_t)&virt_text) + (PGSIZE_2M-1)) & ~(PGSIZE_2M-1))/PGSIZE_2M;

    /* set up each PDE for 2MiB virtual mapping in the PD, for kernel quarter */
	for (int jj = 0; jj < pages; jj++) {
		pd3->table_u64[jj] = (uint64_t)jj * PGSIZE_2M;
		pd3->table_pe[jj].present = 1;
		pd3->table_pe[jj].last    = 1;
		pd3->table_pe[jj].write   = 1;
		pd3->table_pe[jj].global  = 1;
	}

	printf("RAM: map done\n");

	/* TODO do we need to map these additional memory areas yet, or wait
	 * for device initialisation */
#if 0
	if(mbi->flags & MULTIBOOT_INFO_MEM_MAP) {
		memory_map_t *mm;
		for( mm = (memory_map_t *)(uint64_t)mbi->mmap_addr;
				(unsigned long)mm < mbi->mmap_addr + mbi->mmap_length;
				mm = (memory_map_t *)((unsigned long)mm + mm->size +
					sizeof(mm->size)) )
		{
			uintptr_t base = mm->base_addr_high;
			base <<= 32;
			base |= mm->base_addr_low;

			uintptr_t len = mm->length_high;
			len <<= 32;
			len |= mm->length_low;

			int64_t pgsize;

			if (mm->type == MULTIBOOT_MEMORY_RESERVED && base < (uintptr_t)&kernel_start && base > (uintptr_t)&kernel_end)
				for (uintptr_t from = base; from < base + len;) {
					if ((pgsize = get_pe_size(kernel_pd, from)) != 0) {
						from += pgsize;
						continue;
					}
					if ( ((from % PGSIZE_2M) == 0) && (from + PGSIZE_2M) < (base + len) ) {
						create_page_entry_2m(kernel_pd, from, from, PEF_P|PEF_W|PEF_G, NULL);
						from += PGSIZE_2M;
					} else {
						create_page_entry_4k(kernel_pd, from, from, PEF_P|PEF_W|PEF_G, NULL);
						from += PGSIZE_4K;
					}
				}
		}
	}
#endif

	//kern_mem_end = end;

	/* repare the kernel memory allocator */
	memset(&kern_pool, 0, sizeof(kern_pool));
	pool_page_num = 4;

	printf("RAM: about to set kernel_pd\n");
	set_cr3(kernel_pd);
	printf("RAM: kernel_pd installed\n");

	kern_heap_top = kern_mem_end;
	kern_heap_top = (kern_heap_top + (PGSIZE_2M - 1)) & ~(PGSIZE_2M - 1);

	printf("RAM: kern_heap_top set to 0x%lx\n", kern_heap_top);
	//print_mm(kernel_pd);

	/* initialise the kernel memory pools */
	for(i = 0; i < KERN_POOLS; i++)
		do_one_pool();
	
	mem_init = true;
	printf("RAM: mem_init = true\n");
	/* *** kmalloc will now work properly *** */

    /* TODO - make this work as better way of storing PD/PT 
     * currently this is unused */

    /*
	vpt_t *kernel_vpt = new_vpt(kernel_pd, NULL);
	kernel_vpt->entries[0] = new_vpt(&frames[0], kernel_vpt);
	kernel_vpt->entries[0]->entries[0] = new_vpt(&frames[1], kernel_vpt->entries[0]);
	kernel_vpt->entries[0]->entries[3] = new_vpt(&frames[2], kernel_vpt->entries[0]);
    */

	/* setup the task to frame allocation */
	//const size_t taskbm_len = total_frames * sizeof(pid_t);
	const size_t lockbm_len = total_frames * sizeof(unsigned char);

    /*
	printf("RAM: about to alloc taskbm\n");
	taskbm = kmalloc(taskbm_len, "taskbm",NULL,0);
	if(!taskbm) {
		printf("PANIC: failed to allocate taskbm\n");
		while(true) hlt();
	}

	printf("RAM: taskbm at 0x%p with 0x%lx entries using 0x%lx bytes\n", 
			(void *)taskbm, 
			total_frames, 
			taskbm_len);
	memset((char *)taskbm, -1, taskbm_len);
    */

    lockbm = kmalloc(lockbm_len, "lockbm", NULL, 0);
    printf("RAM: lockbm at 0x%p with 0x%lx entries using 0x%lx bytes\n",
            (void *)lockbm,
            total_frames,
            lockbm_len);
    memset(lockbm, 0, lockbm_len);

	//print_mm(kernel_pd);
    
#ifdef BACKUP_PD
    if ((backup_kernel_pd = alloc_pd(NULL)) == NULL) {
        printf("PANIC: unable to allocate backup_kernel_pd");
        while(true) hlt();
    }

    pt_t *dr_frames = find_n_frames(KERN_PD_FRAMES, 0, false);
    memset(dr_frames, 0, KERN_PD_FRAMES * PGSIZE_4K);
#undef KERN_PD_FRAMES

    pdpt = &dr_frames[0];
    pd0  = &dr_frames[1];
    pd3  = &dr_frames[2];

    backup_kernel_pd->table_u64[0] = (uintptr_t)pdpt;
    backup_kernel_pd->table_pe[0].present = 1;

    pdpt->table_u64[0] = (uintptr_t)pd0;
    pdpt->table_pe[0].present = 1;
    pdpt->table_pe[0].write = 1;

	pdpt->table_u64[3] = (uintptr_t)pd3;
	pdpt->table_pe[3].present = 1;
	pdpt->table_pe[3].write   = 1;

    for (int jj = 0; jj < 4; jj++) {
        pd0->table_u64[jj] = (uint64_t)jj * PGSIZE_2M;
        pd0->table_pe[jj].present = 1;
        pd0->table_pe[jj].write   = 1;
        pd0->table_pe[jj].global  = 1;
        pd0->table_pe[jj].last    = 1;
    }

    for (int jj = 0; jj < pages + 1; jj++) {
        pd3->table_u64[jj] = (uint64_t)jj * PGSIZE_2M;
        pd3->table_pe[jj].present = 1;
		pd3->table_pe[jj].last    = 1;
		pd3->table_pe[jj].write   = 1;
		pd3->table_pe[jj].global  = 1;
    }
#endif

    //print_mm(kernel_pd);
    //print_mm(backup_kernel_pd);
}

static void setup_pit(const uint32_t freq)
{
	// 1.193182 MHz

	const uint32_t req = (PIT_FREQ / freq);
	const unsigned char l = (unsigned char)(req & 0xff);
	const unsigned char h = (unsigned char)((req>>8) & 0xff);

	// PIT_BINARY|PIT_OP_M2|PIT_MODE_LOHI

	outportb(0x43, (unsigned char)0x36);

	outportb(0x40, l);
	outportb(0x40, h);
}

#ifdef WANT_SERIAL
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
#endif

static const unsigned char idle_task_code[] = {
	0xfb,
	0xf3, 0x90,		// PAUSE 
	0xeb, 0xfb		// JMP -4
};

static void create_tasks(bool has_root)
{
	uint8_t *tmp,*tmp2;
	//pt_t *idle_pd = NULL;//, *pd = NULL;
	struct task *idle_task, *init_task;

	memset(tasks, 0, sizeof(struct task) * NUM_TASKS);

	idle_task = &tasks[0];
    init_task = &tasks[1];

	/* set-up idle task */

    idle_task->pid = 0;
	idle_task->pd = kernel_pd;

	if ((tmp = kmalloc(sizeof(idle_task_code), "idle_task_code", idle_task, 0)) == NULL) {
		printf("PANIC: no pages for idle task\n");
		while(1) hlt();
	}
    memcpy(tmp, &idle_task_code, sizeof(idle_task_code));
    
	if ((tmp2 = kmalloc_align(STACK_SIZE, "idle_task_stack", idle_task, KMF_ZERO)) == NULL) {
		printf("PANIC: no pages for whatever this is\n");
		while(1) hlt();
	}

	setup_task(idle_task, (uint64_t)tmp, KERNEL_TASK, kernel_pd, "idle", ((uint64_t)tmp2) + STACK_SIZE - 8, 0);
	set_task_state(idle_task,  STATE_RUNNING);
	idle_task->tss.rflags |= F_IF;

	if(!has_root) {
		printf("init: no root\n");
		kfree(tmp2);
		kfree(tmp);
		return;
	}

	/* Set up init task */

    init_task->pid = 1;

	if ((init_task->pd = alloc_pd(init_task)) == NULL) {
		printf("PANIC: cannot kmalloc init_task PT\n");
		while(1) hlt();
	}

	if (clone_mm(kernel_pd, init_task->pd, init_task->pid, true)) {
        printf("PANIC: unable to clone_mm kernel_pd\n");
        while(1) hlt();
    }

	char *cmd = strdup("/bin/sh");
	char **argv = kmalloc(sizeof(char *) * 2, "init_argv", init_task, KMF_ZERO);
	char **envp = kmalloc(sizeof(char *) * 2, "init_envp", init_task, KMF_ZERO);

	if (!argv || !envp || !cmd) {
		printf("init: unable to kmalloc argv/envp\n");
		return;
	}

	argv[0] = strdup("/bin/sh");
	envp[0] = strdup("SHLVL=0");

	if (!argv[0] || !envp[0]) {
		printf("init: unable to kmalloc argv[0]/envp[0]\n");
        kfree(cmd); kfree(argv); kfree(envp);
		return;
	}

	curtask = 1;
	init_task->pgid = init_task->pid;

	/* broken as we've not switched to user space? */
	int rc;
	if ((rc = sys_execve(cmd, argv, envp)) < 0) {
		printf("init: failed to execute init: error %d\n", GET_ERR(rc));
		while(1) hlt();
	}

	//printf("init: init [heap=%p:%p]\n", init_task->heap_start, init_task->heap_end);
	printf("init: create_tasks: done\n");
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

static void setup_msr(void)
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


#define	_cpuid(func1,func2,ax,bx,cx,dx) \
	__asm__ volatile("cpuid":"=a"(ax),"=b"(bx),"=c"(cx),"=d"(dx):"a"(func1),"c"(func2));

/*
__attribute__((nonnull))
static void init_lapic(volatile struct lapic *l)
{
	printf("lapic: address:%p\n", (void *)l);
	if (!get_pe_size(kernel_pd, (uintptr_t)l))
		if (!create_page_entry_4k(kernel_pd, (uintptr_t)l, (uintptr_t)l, PEF_P|PEF_W|PEF_G, NULL)) {
			printf("lapic: unable to map\n");
			return;
		}
	printf("lapic: mapping 4k %0lx to %0lx\n", (uintptr_t)l, (uintptr_t)l);
	printf("lapic: ver:%x\n", l->ver_reg & 0xff);
}
*/

#define RAX 0
#define RBX 1
#define RCX 2
#define RDX 3

static void cpu_init(void)
{
	uint32_t ret[4];
	unsigned char id[13];
	struct cpu *cpu = &cpus[0];
#ifdef WANT_APIC
	APICbar ab;
#endif

	_cpuid(0x0, 0x0, ret[0], ret[1], ret[2], ret[3]);

	memcpy(&id[0], &ret[1], 4);
	memcpy(&id[4], &ret[3], 4);
	memcpy(&id[8], &ret[2], 4);
	id[12] = '\0';

	printf("cpu_init: cpu[0]: \"%s\" max:0x%02x\n", id, ret[RAX]);

	const uint32_t max = ret[RAX];
	const uint32_t platform_info = read_msr(MSR_PLATFORM_INFO);

	printf("cpu_init: platform_info:%x\n", platform_info);

	if(max >= 0x15) {
		_cpuid(0x15, 0x0, ret[0], ret[1], ret[2], ret[3]);
		printf("cpu0: TSC: %x %x %x %x\n",
				ret[0], ret[1], ret[2], ret[3]);
	}

#ifdef WANT_APIC
	ab.b = read_msr(MSR_APIC_BASE);
	printf("cpu0: MSR_APIC_BAR: cpu_is_bsp?:%x, apic_enable:%x, ", 
			ab.a.processor_is_bsp, ab.a.apic_enable);
	printf("apic_base:%lx\n", APIC_BASE(ab));
	if (!get_pe_size(kernel_pd, APIC_BASE(ab))) {
		if (!create_page_entry_4k(kernel_pd, APIC_BASE(ab), APIC_BASE(ab), PEF_P|PEF_W|PEF_G, NULL))
			printf("cpu0: valid to map APIC_BASE(%lx)\n", APIC_BASE(ab));
#ifdef BACKUP_PD
		if (!create_page_entry_4k(backup_kernel_pd, APIC_BASE(ab), APIC_BASE(ab), PEF_P|PEF_W|PEF_G, NULL))
			printf("cpu0: valid to map APIC_BASE(%lx)\n", APIC_BASE(ab));
#endif
    }
	cpu->lapic = (volatile struct lapic *)APIC_BASE(ab);

	ab.a.apic_enable = 1;
	write_msr(MSR_APIC_BASE, ab.b);

	init_lapic(cpu->lapic);
#endif

	_cpuid(0x1, 0x0, ret[0], ret[1], ret[2], ret[3]);
	printf("cpu0.1.EAX: 0x%08x:", ret[RAX]);
	printf("\n");
	printf("cpu0.1.EBX: 0x%08x:", ret[RBX]);
	printf("\n");
	printf("cpu0.1.ECX: 0x%08x:", ret[RCX]);
	printf("\n");
	printf("cpu0.1.EDX: 0x%08x:", ret[RDX]);
	printf("\n");

	num_cpus = ((ret[RAX] & 0x00ff0000)>>16);

	if(!num_cpus) 
		num_cpus=1;

	printf("cpu: num_cpus:%x\n",num_cpus); 
	printf("cpu0.1: ");
	printf("stepping:%x ", 
			(cpu->stepping = (ret[RAX] & 0x0000000f)));
	printf("model:%x ", 
			(cpu->model    = (((ret[RAX] & 0x000000f0)>>4)|((ret[RAX] & 0x000f0000)>>16))));
	printf("family:%x ", 
			(cpu->family   = ((((ret[RAX] & 0x00000f00)>>8)|((ret[RAX] & 0x00f00000)>>20)))));
	printf("id:%x ", 
			(cpu->apic_id  = ((ret[RBX] & 0xff000000)>>24)));
	printf("type:%x ",
			(ret[RAX] & 0x3000) >> 12);
	printf("\n");

	printf("cpu0.1.EBX: 0x%08x:", ret[RBX]);
	const char *const feat_edx[32] = {
		"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic",
		NULL, "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "psn",
		"clfsh", NULL, "ds", "acpi", "mmx", "fxsr", "sse", "sse", "ss",
		"htt", "tm", "ia64", "pbe"
	};
	for (int i = 0; i < 32; i++)
		if (feat_edx[i] != NULL && (ret[RDX] & (1<<i)))
			printf(" %s", feat_edx[i]);
	printf("\n");


	_cpuid(0x7, 0x0, ret[0], ret[1], ret[2], ret[3]);
	printf("cpu0.7.EBX: 0x%08x:", ret[RBX]);
	const char *const ext_feat[32] = {
		"fsgsbase", "IA32_TSC_ADJUST", "sgx", "bmi1", "hle", "avx2",
		"FDP_EXCPTN_ONLY", "smep", "bmi2", "erms", "invpcid",
		"rtm", "pqm", "FPU CS&DS depn", "mpx", "pqe", "avx512_f",
		"avx512_dq", "rdseed", "adx", "smap", "avx512_ifma", "pcommit",
		"clfushopt", "clwb", "intel_pt", "avx512_pf", "avx512_er",
		"avx512_cd", "sha", "avx512_bw", "avx512_vl" };
	for (int i = 0; i < 32; i++)
		if (ext_feat[i] != NULL && (ret[RBX] & (1<<i)))
			printf(" %s", ext_feat[i]);
	printf("\n");
	printf("cpu0.7.ECX: 0x%08x:", ret[RCX]);
	printf("\n");

	_cpuid(0x80000001, 0x0, ret[0], ret[1], ret[2], ret[3]);
	printf("cpu0.AMD1.EDX: 0x%08x", ret[RDX]);
	const char *const ext_proc[32] = {
		"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic",
		NULL, "syscall", "mtrr", "pge", "mca", "cmov", "pat", "pse36", NULL,
		"mp", "nx", NULL, "mmxext", "mmx", "fxsr", "fxsr_opt", "pdpe1gb",
		"rdtscp", NULL, "lm", "3dnowext", "3dnow"
	};
	for (int i = 0; i < 32; i++)
		if (ext_proc[i] != NULL && (ret[RDX] & (1<<i)))
			printf(" %s", ext_proc[i]);
	printf("\n");
}

#undef RAX
#undef RBX
#undef RCX
#undef RDX

#ifdef WANT_PCI
static void pci_init(void)
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
#endif

static void dev_init(void)
{
	printf("dev_init: ");
	add_dev(DEV_ID(CON_MAJOR,CON_MINOR), DEV_CHAR, 
			&console_char_ops, "con", NULL);
	printf("con ");
	add_dev(DEV_ID(TTY_MAJOR,NUL_MINOR), DEV_CHAR,
			&char_special_ops, "tty_null", NULL);
	printf("tty_null ");
#ifdef WANT_RAMDISK
	for(int i=0;i<NUM_RD;i++) 
	{
		add_dev(DEV_ID(RD_MAJOR,RD_0_MINOR+i), DEV_BLOCK, 
				&ram_block_ops, "ram", NULL);
		printf("ram(%x) ", i);
	}
#endif
#ifdef WANT_SERIAL
	add_dev(DEV_ID(SER_MAJOR,SER_0_MINOR), DEV_CHAR,
			&serial_char_ops, "ser", NULL);
	printf("ser(0) ");
#endif
	printf("\n");
}

#ifdef WANT_NET
static inline void proto_init(void)
{
	printf("proto_init: ");
#ifdef WANT_IP
	add_dev(NETPROTO_IP, DEV_PROTO, &ip_proto_ops, "ip", NULL);
	printf("ip ");
#endif
	printf("\n");
}

static void net_init(void)
{
	printf("net_init: ");
	//	add_dev(NETDEV_PPP, DEV_NET, &ppp_net_ops, "ppp");
	//	printf("ppp ");
	//	add_dev(NETDEV_SLIP, DEV_NET, &slip_net_ops, "slip");
	//	printf("slip ");
	printf("\n");
}
#endif

static void fs_init(void)
{
	printf("fs_init: ");
#ifdef WANT_RAMFS
	printf("ramfs ");
	add_dev(0, DEV_FS, &ramfs_ops, "ramfs", NULL);
#endif
#ifdef WANT_FAILFS
	printf("failfs ");
	add_dev(0, DEV_FS, &failfs_ops, "failfs", NULL);
#endif
	printf("\n");
}

__attribute__((nonnull,noreturn))
void kernmain(const unsigned long magic, const multiboot_info_t *const mbd)
{
    __asm__ volatile ("":::"memory");
	nosched = false;
    tick = curtask = 0;
	firsttask = 1;
	devs = NULL;

#ifdef WANT_SERIAL
	setup_serial(COM1, 115200);
#endif
#ifdef WANT_VGA
	setup_vga();
#endif
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
#ifdef WANT_ACPI
	acpi_probe();
#endif
#ifdef WANT_NET
	proto_init();
#endif
#ifdef WANT_PCI
	pci_init();
#endif
	file_init();
	dev_init();
	fs_init();
#ifdef WANT_NET
	net_init();
#endif
	syscall_init();

	root_mnt = NULL;
	root_fsent = NULL;

	struct block_dev *hd = NULL;
	struct fileh *fh1 = NULL, *fh2 = NULL;

#ifdef WANT_RAMDISK
	if((hd = find_dev(DEV_ID(RD_MAJOR, RD_0_MINOR), DEV_BLOCK)) == NULL) {
		printf("init: unable to find root device (%d,%d)\n", RD_MAJOR, RD_0_MINOR);
		goto no_root;
	}
#endif

#ifdef WANT_RAMFS
	if((root_mnt = do_mount(hd, NULL, &ramfs_ops)) == NULL) {
		printf("init: unable to mount %s filesystem on /\n", ramfs_ops.name);
		goto no_root;
	}
#endif
	
	root_fsent = root_mnt->root;

#ifdef WANT_IDE
	hd = find_dev(DEV_ID(IDE_MAJOR, 0), DEV_BLOCK);
#endif
	if(hd) {
		//struct mount *fail_mnt;
		//int rc;

//		dump_fsents();
	//	printf("\ninit: trying to mount /mnt\n");
	//	void *tmp = resolve_file("/mnt", root_fsent, &rc);
	//	if (!tmp) {
	//		printf("init: cannot find /mnt\n");
	//		goto no_root;
	//	}
	//	if ((fail_mnt = do_mount(hd, tmp, &failfs_ops)) == NULL) {
	//		printf("init: failed\n");
	//		goto no_root;
	//	}
	//	printf("init: /mnt mounted OK\n");
//		dump_fsents();
//		printf("\n\n");
//		while(1) hlt();

	
	//	printf("init: open newfile\n");
	//	if((fh1 = do_open("/mnt/newfile.txt", NULL, O_CREAT|O_RDWR, 0755, &rc)) == NULL)
	//		printf("init: can't open file: %d: %s\n", rc, strerror(rc));

		//whie(1) hlt();
//		dump_fsents();
//		printf("\n\n");

	//	printf("init: open newfile2\n");
	//	if((fh2 = do_open("/mnt/newfile2.txt", NULL, O_CREAT|O_RDWR, 0755, &rc)) == NULL)
	//		printf("init: can't open file: %d: %s\n", rc, strerror(rc));
//		dump_fsents();
//		printf("\n\n");

	//	printf("init: mkdir tmp\n");
	//	if((do_mkdir(NULL, "/mnt/tmp", 0755)) < 0)
	//		printf("init: can't mkdir: %d: %s\n", rc, strerror(rc));
//		dump_fsents();
//		printf("\n\n");

		//printf("init: mkdir tmp2\n");
		//if((do_mkdir(NULL, "/mnt/tmp2", 0755)) < 0)
	//		printf("init: can't mkdir: %d: %s\n", rc, strerror(rc));
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
	printf("init: creating initial tasks\n");
	create_tasks((root_mnt != NULL));
	curtask = firsttask = 0;

	/* enable rd/wr fs/gs base instructions for usermode */
	//set_cr4(get_cr4()|(1<<16));

	write_msr(MSR_KERNEL_GSBASE, (uint64_t)&tasks[firsttask]);
	write_msr(MSR_GSBASE, 0x0);

	global_tss.rsp0 = (uint64_t)tasks[firsttask].kernelsptr;
	global_tss.ist1 = (uint64_t)kmalloc_align(STACK_SIZE, "#DF stack", NULL,KMF_ZERO);

	if(root_mnt)
		for(int i = 1; i <= 1; i++) {
			printf("init: fd[0] for task %i\n", i);
			if( (tasks[i].fps[0] = do_open("/dev/tty", &tasks[i], O_RDONLY, 0, NULL, 0)) == NULL )
				printf("init: unable to open stdin\n");
			printf("init: fd[1] for task %i\n", i);
			if( (tasks[i].fps[1] = do_open("/dev/tty", &tasks[i], O_WRONLY, 0, NULL, 0)) == NULL )
				printf("init: unable to open stdout\n");
			printf("init: fd[2] for task %i\n", i);
			if( (tasks[i].fps[2] = do_open("/dev/tty", &tasks[i], O_WRONLY, 0, NULL, 0)) == NULL )
				printf("init: unable to open stderr\n");
		}

	if(fh1)
		do_close(fh1, NULL);
	if(fh2)
		do_close(fh2, NULL);
	flush_fsents();

	printf("init: DONE\n");

	/* printf("init: gousermode rip=%lx cs=%lx rflags=%lx rsp=%lx ss=%lx\n", tasks[firsttask].tss.rip, tasks[firsttask].tss.cs, tasks[firsttask].tss.rflags, tasks[firsttask].tss.rsp, tasks[firsttask].tss.ss); */

	printf("init: switching to CPL3 and PID %d\n", firsttask);
	boot_done = true;
	gousermode(
			tasks[firsttask].tss.rip,
			tasks[firsttask].tss.cs,
			tasks[firsttask].tss.rflags,
			tasks[firsttask].tss.rsp,
			tasks[firsttask].tss.ss
			);
}
