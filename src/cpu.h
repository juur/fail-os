#ifndef _CPU_H
#define _CPU_H

#include	"klibc.h"

#define cli() __asm__ volatile("cli")
#define sti() __asm__ volatile("sti")
#define hlt() __asm__ volatile("hlt")
#define _brk()	__asm__ volatile("xchg %bx,%bx")
#define pause() __asm__ volatile("pause")
#define getrflags(b) __asm__ volatile("pushf\n\tpop %%rax\n\tmovq %%rax,%0":"=r"(b)::"%rax")

/* memory map
 * 0x0000000 - 0xffffff	Kernel space, 4x 4MiB pages linear=physical
 * 0x10000000 			User space, 4KiB pages linear!=physical. Starts with 4k stack.
 *
 */

/* RFLAGS bits */
#define F_CF	0x0001
#define F_RES0	0x0002
#define F_PF	0x0004
#define F_RES1	0x0008
#define	F_AF	0x0010
#define	F_RES2	0x0020
#define	F_ZF	0x0040
#define F_SF	0x0080
#define	F_TF	0x0100
#define	F_IF	0x0200
#define	F_DF	0x0400
#define	F_OF	0x0800

#define F_RF	0x00010000
#define	F_VM	0x00020000
#define	F_AC	0x00040000
#define	F_VIF	0x00080000
#define	F_VIP	0x00100000
#define	F_ID	0x00200000

/* CPU Exceptions see cpu.c:exceptions[] */
#define CPUE_DE		0x00
#define CPUE_DB		0x01
#define CPUE_NMI	0x02
#define CPUE_BP		0x03
#define CPUE_OF		0x04
#define	CPUE_BR		0x05
#define	CPUE_UD		0x06
#define	CPUE_NM		0x07
#define	CPUE_DF		0x08
#define	CPUE_TS		0x0a
#define	CPUE_NP		0x0b
#define	CPUE_SS		0x0c
#define	CPUE_GP		0x0d
#define	CPUE_PF		0x0e
#define CPUE_MF		0x10
#define CPUE_AC		0x11
#define	CPUE_MC		0x12
#define	CPUE_XM		0x13
#define	CPUE_VE		0x14
#define CPUE_CP		0x15
#define CPUE_SF		0x30

/* CR0 bits */
#define CR0_PE (1<<0)
#define CR0_MP (1<<1)
#define CR0_EM (1<<2)
#define CR0_TS (1<<3)
#define CR0_ET (1<<4)
#define CR0_NE (1<<5)
#define CR0_WP (1<<16)
#define CR0_AM (1<<18)
#define CR0_NW (1<<29)
#define CR0_CD (1<<30)
#define CR0_PG (1<<31)

/* CR4 bits */
#define CR4_VME        (1<<0)
#define CR4_PVI        (1<<1)
#define CR4_TSD        (1<<2)
#define CR4_DE         (1<<3)
#define CR4_PSE        (1<<4)
#define CR4_PAE        (1<<5)
#define CR4_MCE        (1<<6)
#define CR4_PGE        (1<<7)
#define CR4_PCE        (1<<8)
#define CR4_OSFXSR     (1<<9)
#define CR4_OSXMMEXCPT (1<<10)
#define CR4_UMIP       (1<<11)
#define CR4_LA57       (1<<12)
#define CR4_VMXE       (1<<13)
#define CR4_SMXE       (1<<14)
#define CR4_FSGSBASE   (1<<16)
#define CR4_PCIDE      (1<<17)
#define CR4_OSXSAVE    (1<<18)
#define CR4_SMEP       (1<<20)
#define CR4_SMAP       (1<<21)
#define CR4_PKE        (1<<22)

/* Legacy Mode system-segment descriptor types */
/* 0 is illegal */
#define GDT_TYPE_TSSAVAIL16	0x01
#define GDT_TYPE_LDT32		0x02
#define GDT_TYPE_TSSBUSY16	0x03
#define GDT_TYPE_CALL16		0x04
#define GDT_TYPE_TASK32		0x05
#define GDT_TYPE_INT16		0x06
#define GDT_TYPE_TRAP16		0x07
/* 8 is illegal */
#define GDT_TYPE_TSSAVAIL32	0x08
/* A is illegal */
#define GDT_TYPE_TSSBUSY32	0x0b
#define GDT_TYPE_CALL32		0x0c
/* D is illegal */
#define GDT_TYPE_INT32		0x0e
#define GDT_TYPE_TRAP32		0x0f

#define GDT_TYPE_DS32		0x12
#define GDT_TYPE_CS32		0x13

/* Long Mode system-segment descriptor types */

/* 0, 1 are illegal */
#define GDT_TYPE_LDT64		0x02
/* 3-8 are illegal */
#define GDT_TYPE_TSSAVAIL64	0x09
/* a is illegal */
#define GDT_TYPE_TSSBSY64	0x0b
#define GDT_TYPE_CALL64		0x0c
/* d is illegal */
#define GDT_TYPE_INT64		0x0e
#define GDT_TYPE_TRAP64		0x0f
/* these are not official types */
#define GDT_TYPE_DS64		0x10
#define	GDT_TYPE_CS64		0x11

#define GTF_R	0x01		// CS: Readable (Execute is implicit)
#define	GTF_W	0x01		// DS: Writable 

#define GTF_C	0x02		// CS: Conforming
#define GTF_E	0x02		// DS: Expand-Down

#define GTF_P	0x04		// Present
//#define GTF_L	0x08		// Long Mode (implied by function)

#define GTF_D	0x10		// CS32 Default Operand Size (0=32bit 1=32Bit)
#define GTF_B	0x10		// Default Stack Size (1=32Bit)

#define GTF_G	0x20		// Granularity

#define GTF_AVL	0x40		// AVL

#define GTF_DPL	0x03

#define CPL_0	0x00
#define CPL_1	0x01
#define CPL_2	0x02
#define CPL_3	0x03

/* 
 * Long Mode:   AMD64 Figure 4-20 & 4-21 
 * Legacy Mode: AMD64 Figure 4-14 & 4-15 
 */
struct gdt_entry
{
	/* first word */
	uint16_t	limit_low;		// 00-15
	uint16_t	base_low;		// 16-31

	/* second word */
	uint8_t		base_middle;	// 00-07

	/* for system selectors these four bits int type:4 see GDT_TYPE_* */
	unsigned	accessed:1;		// 08
	unsigned	readable:1;		// 09		CS:Readable		DS:Writeable
	unsigned	ce:1;			// 10		CS:Conforming	DSExpand-Down
	unsigned	res:1;			// 11		CS:1			DS:0

	unsigned	issegment:1;	// 12		CS:1			DS:1
	unsigned	dpl:2;			// 13-14
	unsigned	present:1;		// 15

	unsigned	limit_middle:4;	// 16-19
	unsigned	avl:1;			// 20
	unsigned	islong:1;		// 21
	unsigned	def:1;			// 22		CS:1=32B		DS:				SS:1=32B
	unsigned	granularity:1;	// 23

	uint8_t		base_high;		// 24-31
} __attribute__((packed));

/* this covers system selectors that consume 2 slots for +8 and +12 uint32s */
struct gdt_entry_high
{
	uint32_t	base_very_high;
	uint32_t	empty;
} __attribute__((packed));

struct gdt64_ptr
{
	uint16_t	limit;
	uint64_t	base;
} __attribute__((packed));

/* this should be some kind of union with gdt_entry+gdt_entry_high */
/* AMD64 Figure 4-23 */
struct callgate_entry
{
	/* gdt_entry */
	uint16_t	target_low;
	uint16_t	sel;

	uint8_t		res0;
	
	unsigned	type:4;
	unsigned	always0a:1;
	unsigned	dpl:2;
	unsigned	present:1;

	uint16_t	target_high;

	/* gdt_entry_high*/
	uint32_t	target_very_high;

	uint8_t		res1;				//  0- 7
	unsigned	always0b:5;			//  8-12
	unsigned	res2:27;			// 13-31
} __attribute__((packed));

/* AMD64 Figure 4-22 */
struct gdt_sysdesc_64 {
	uint16_t	limit_low;
	uint16_t	base_low;

	uint8_t		base_middle;
	unsigned	type:4;
	unsigned	always0a:1;
	unsigned	dpl:2;
	unsigned	present:1;

	unsigned	limit_middle:4;
	unsigned	avl:1;
	unsigned	always0b:2;
	unsigned	granularity:1;
	uint8_t		base_high;

	uint32_t	base_very_high;

	uint8_t		always0c:8;
	unsigned	always0d:5;
	unsigned	always0e:27;
} __attribute__((packed));

/* this should be some kind of union with gdt_entry+gdt_entry_high */
/* Figure 4-24 */
struct idt_entry
{
	/* gdt_entry */
	uint16_t	target_low;
	uint16_t	target_sel;

	unsigned	ist:3;
	unsigned	res0:5;

	unsigned	type:4;				// see GDT_TYPE_*
	unsigned	always0:1;
	unsigned	dpl:2;
	unsigned	present:1;

	uint16_t	target_high;

	/* gdt_entry_high*/
	uint32_t	target_very_high;
	uint32_t	res1;
} __attribute__((packed));

struct idt64_ptr
{
	uint16_t	limit;
	uint64_t	base;
} __attribute__((packed));

struct regs
{
	uint64_t	ds, es, fs, gs;			// 0x00	
	uint64_t	r15, r14, r13, r12; 	// 0x20
	uint64_t	r11, r10, r9, r8;		// 0x40
	uint64_t	rdi, rsi, rbp;			// 0x60
	uint64_t	rdx, rcx, rbx, rax;		// 0x78

	uint64_t	int_num;				// 0x98
	uint64_t	error_code;				// 0xa0
	uint64_t	rip;					// 0xa8
	uint64_t	cs;						// 0xb0
	uint64_t	rflags;					// 0xb8
	uint64_t	rsp;					// 0xc0
	uint64_t	ss;						// 0xc8
} __attribute__((packed));

#ifdef _CPU_C
const int reg_size = sizeof(struct regs);
#else
extern const int reg_size;
#endif

#define	IDT_SIZE	256

#define _SSIZE		sizeof(struct gdt_entry)

/* SYSCALL/SYSRET make assumptions as to ordering here */
/* do not change the order of these without looking at IA32_STAR in setup_msr */

#define _NULL_CS	(0x00*_SSIZE)	// 0x00
#define	_KERNEL_CS	(0x01*_SSIZE)	// 0x08
#define	_KERNEL_DS	(0x02*_SSIZE)	// 0x10
#define _USER32_CS	(0x03*_SSIZE)	// 0x18
#define _USER32_DS	(0x04*_SSIZE)	// 0x20
#define _USER_CS	(0x05*_SSIZE)	// 0x28
#define	_USER_DS	(0x06*_SSIZE)	// 0x30
#define _TSS_CS		(0x10*_SSIZE)	/* 0x40 - takes up 2 slots */

#define GDT_SIZE	0x20

#define MSR_EFER				0xc0000080
#define MSR_STAR				0xc0000081
#define	MSR_LSTAR				0xc0000082
#define MSR_CSTAR				0xc0000083
#define MSR_SFMASK				0xc0000084
#define MSR_FSBASE				0xc0000100
#define MSR_GSBASE				0xc0000101
#define MSR_KERNEL_GSBASE		0xc0000102
#define MSR_APIC_BASE   		0x0000001b
#define MSR_PLATFORM_INFO		0x000000ce

#define MAX_CPU					32

/* Table 10-1 Local APIC Reigster Address Map 
 * each field is 32b but 128b aligned
 * const fields are RO
 * some fields are WO
 */
struct lapic {
	const uint32_t	res00 __attribute__((aligned(16)));
	const uint32_t	res01 __attribute__((aligned(16)));

	const uint32_t	id_reg __attribute__((aligned(16)));
	uint32_t		ver_reg __attribute__((aligned(16)));

	const uint32_t	res10 __attribute__((aligned(16)));
	const uint32_t	res11 __attribute__((aligned(16)));
	const uint32_t	res12 __attribute__((aligned(16)));
	const uint32_t	res13 __attribute__((aligned(16)));

	uint32_t		tpr __attribute__((aligned(16)));
	const uint32_t	apr __attribute__((aligned(16)));
	const uint32_t	ppr __attribute__((aligned(16)));
	uint32_t		eoi __attribute__((aligned(16))); /* WO */
	const uint32_t	rrd __attribute__((aligned(16)));
	uint32_t		ldr __attribute__((aligned(16)));
	uint32_t		dfr __attribute__((aligned(16)));
	uint32_t		sivr __attribute__((aligned(16)));

	/* 256 bits */
	const uint32_t	isr0 __attribute__((aligned(16)));
	const uint32_t	isr1 __attribute__((aligned(16)));
	const uint32_t	isr2 __attribute__((aligned(16)));
	const uint32_t	isr3 __attribute__((aligned(16)));
	const uint32_t	isr4 __attribute__((aligned(16)));
	const uint32_t	isr5 __attribute__((aligned(16)));
	const uint32_t	isr6 __attribute__((aligned(16)));
	const uint32_t	isr7 __attribute__((aligned(16)));

	/* TODO each of these is 128b aligned faff */
	const uint32_t	tmr[8]; /* 256 bits */
	const uint32_t	irr[8]; /* 256 bits */
	const uint32_t	esr;
	const uint32_t	res2[6];
	uint32_t		lvt_cmci;
	uint64_t		icr;
	uint32_t		lvt_tr;
	uint32_t		lvt_tsr;
	uint32_t		lvt_pmcr;
	uint32_t		lvt_lint0;
	uint32_t		lvt_lint1;
	uint32_t		lvt_err;
	uint32_t		tim_icr;
	const uint32_t	tim_ccr;
	const uint32_t	res3[4];
	uint32_t		tim_dcr;
	uint32_t		res4;
};

struct cpu {
	uint8_t	stepping;
	uint8_t	model;
	uint8_t	family;
	uint8_t	apic_id;
	uint32_t padding;
	volatile struct lapic *lapic;
};

struct timeval {
	uint64_t	tv_sec;
	uint64_t	tv_usec;
};

/*
struct _APICbar {
	unsigned res0:8;
	unsigned processor_is_bsp:1;
	unsigned res1:2;
	unsigned apic_enable:1;
	uint64_t apic_base:40;
	unsigned res2:12;
} __attribute__((packed));
*/

#define APIC_BASE(x) ((uint64_t)(((x).apic_base)<<12))

typedef union {
	struct {
		unsigned res0:8;
		unsigned processor_is_bsp:1;
		unsigned res1:2;
		unsigned apic_enable:1;
		uint64_t apic_base:40;
		unsigned res2:12;
	} __attribute__((packed));
	uint64_t b;
} __attribute__((packed)) APICbar;

struct _STAR {
	uint32_t	syscall_eip;
	uint16_t	syscall_csss;
	uint16_t	sysret_csss;
} __attribute__((packed));

typedef union {
	struct _STAR a;
	uint64_t b;
} __attribute__((packed)) STAR;


#define PF_P	(1 << 0)
#define	PF_WR	(1 << 1)
#define	PF_US	(1 << 2)
#define	PF_RSVD	(1 << 3)
#define	PF_ID	(1 << 4)

#ifdef _CPU_C
const char *bits_PF[] = {
	"Present", "Write", "User", "Reserved", "Instruction", "Protection Key", "Shadow-Stack", NULL
};
#else
extern const char *bits_PF[];

extern volatile struct gdt_entry gdt[GDT_SIZE];
extern volatile struct gdt64_ptr gdtp;
extern volatile struct tss_64 global_tss;
extern volatile struct idt_entry idt[IDT_SIZE];
extern volatile struct idt64_ptr idtp;
extern struct cpu cpus[MAX_CPU];
extern uint8_t num_cpus;
#endif

#include "page.h"

__attribute__((nonnull)) static inline void set_cr3(const pt_t *pml4)
{
	__asm__ volatile("mov %0, %%cr3;nop"::"r"((uint64_t)pml4):"memory");
}

static inline pt_t *get_cr3(void)
{
	uint64_t ret;
	__asm__ volatile("mov %%cr3, %0":"=r"(ret));
	return (pt_t*)ret;
}

static inline uint64_t get_cr2(void)
{
	uint64_t ret;
	__asm__ volatile("mov %%cr2, %0":"=r"(ret));
	return ret;
}

static inline void set_cr0(uint64_t cr0)
{
	__asm__ volatile("mov %0, %%cr0"::"r"(cr0):"memory");
}

static inline uint64_t get_cr0(void)
{
	uint64_t ret;
	__asm__ volatile("mov %%cr0, %0":"=r"(ret));
	return ret;
}

static inline void set_cr4(uint64_t cr4)
{
	__asm__ volatile("mov %0, %%cr4"::"r"(cr4));
}

static inline uint64_t get_cr4(void)
{
	uint64_t ret;
	__asm__ volatile("mov %%cr4, %0":"=r"(ret));
	return ret;
}

static inline void write_msr(const uint32_t msr, const uint64_t value)
{
	register uint32_t eax __asm__ ("rax");
	register uint32_t edx __asm__ ("rdx");

	edx = (uint32_t)((value >> 32) & 0xffffffff);
	eax = (uint32_t)(value & 0xffffffff);

	__asm__ volatile("wrmsr"::"c"(msr),"a"(eax),"d"(edx):"memory");
}

static inline uint64_t read_msr(const uint32_t msr)
{
	//uint64_t ret;
	register uint32_t eax __asm__ ("rax");
	register uint32_t edx __asm__ ("rdx");

	__asm__ volatile("rdmsr":"=a"(eax),"=d"(edx) :"c"(msr));
	/*
	ret = edx;
	ret <<= 32;
	ret |= eax;
	*/

	return ((uint64_t)edx<<32)|eax;
}



void gdt_flush(void);
void idt_flush(void);
void tss_flush(uint16_t tsss);
//void cr3_flush(pt_t *pml4);
//pt_t *get_cr3(void);
//void _idt_main(struct regs r);
//void idt_main(struct regs *r);
void idt_set_gate64(uint8_t num, uint64_t base, uint16_t sel,   uint8_t dpl, uint8_t ist,  uint8_t type);
void gdt_set_gate64(uint8_t num, uint64_t base, uint32_t limit, uint8_t dpl, uint8_t flag, uint8_t type);
void gdt_set_gate32(uint8_t num, uint32_t base, uint32_t limit, uint8_t dpl, uint8_t flag, uint8_t type);
//uint64_t read_msr(uint32_t msr);
//void write_msr(uint32_t msr, uint64_t proc);
void print_reg(const struct regs *r)__attribute__((nonnull));
void spin_lock(int *lock)__attribute__((nonnull));
void spin_unlock(int *lock)__attribute__((nonnull));

#endif

// vim: set ft=c:
