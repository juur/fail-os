#ifndef _CPU_H
#define _CPU_H

#include	"klibc.h"

#ifdef __GNUC__
#define cli() __asm__ __volatile__("cli;")
#define sti() __asm__ __volatile__("sti;")
#define hlt() __asm__ __volatile__("hlt;")
#define _brk()	__asm__ __volatile__("xchg %bx,%bx")
#define pause() __asm__ __volatile__("pause;")
#else
#define cli()
#define sti()
#define hlt()
#define _brk()
#define pause()
#endif

/* memory map
 * 0x0000000 - 0xffffff	Kernel space, 4x 4MiB pages linear=physical
 * 0x10000000 			User space, 4KiB pages linear!=physical. Starts with 4k stack.
 *
 */

#define CPUE_DE	0x0
#define CPUE_DB 0x1
#define CPUE_NMI 0x2
#define CPUE_BP	0x3
#define CPUE_OF	0x4
#define	CPUE_BR	0x5
#define	CPUE_UD	0x6
#define	CPUE_NM	0x7
#define	CPUE_DF	0x8
#define	CPUE_TS	0xa
#define	CPUE_NP	0xb
#define	CPUE_SS	0xc
#define	CPUE_GP	0xd
#define	CPUE_PF	0xe

#define GDT_TYPE_DS		0x10
#define	GDT_TYPE_CS		0x11

#define GDT_TYPE_LDT	0x2
#define GDT_TYPE_TSSA	0x9
#define GDT_TYPE_TSSB	0xb
#define GDT_TYPE_CALL	0xc
#define GDT_TYPE_INT	0xe
#define GDT_TYPE_TRAP	0xf

#define GTF_R	0x01		// Readable (Execute is implicit)
#define	GTF_W	0x01		// Writable 

#define GTF_C	0x02		// Conforming
#define GTF_E	0x02		// Expand-Down

#define GTF_P	0x04		// Present
#define GTF_L	0x08		// Long

#define GTF_D	0x10		// CS/DS Default Operand Size (1=32Bit)
#define GTF_B	0x10		// Default Stack Size (1=32Bit)

#define GTF_G	0x20		// Granularity

#define GTF_DPL	0x03

struct gdt_entry
{
	uint16	limit_low;		// 0-15
	uint16	base_low;		// 16-31

	uint8	base_middle;	// 0-7

	/* for system selectors this are int flag:4 */

	unsigned	access:1;		// 8
	unsigned	rw:1;			// 9 CS or DS
	unsigned	ce:1;			// 10 CS or DS
	unsigned	res:1;			// 11 1=CS, 2=DS if issegment

	unsigned	issegment:1;	// 12
	unsigned	dpl:2;			// 13, 14
	unsigned	present:1;		// 15

	unsigned	limit_middle:4;	// 16-19
	unsigned	avl:1;			// 20
	unsigned	islong:1;		// 21
	unsigned	def:1;			// 22
	unsigned	granularity:1;	// 23

	uint8	base_high;		// 24-31

	//uint32	base_very_high;
	//uint32	empty;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;

struct gdt_entry_high
{
	uint32	base_very_high;
	uint32	empty;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;
struct gdt64_ptr
{
	uint16	limit;
	uint64	base;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;
struct idt_entry
{
	uint16	target_low;
	uint16	sel;

	unsigned	ist:3;
	unsigned	res:5;

	unsigned	type:4;
	unsigned	always0:1;
	unsigned	dpl:2;
	unsigned	present:1;

	uint16	target_high;

	uint32	target_very_high;

	uint32	ignore;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;
struct idt64_ptr
{
	uint16	limit;
	uint64	base;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;
struct regs
{
	uint64	ds, es, fs, gs;			// 0x00	
	uint64	r15, r14, r13, r12; 	// 0x20
	uint64	r11, r10, r9, r8;		// 0x40
	uint64	rdi, rsi, rbp;			// 0x60
	uint64	rdx, rcx, rbx, rax;		// 0x78
	uint64	int_num;				// 0x98
	uint64	error_code;				// 0xa0
	uint64	rip;					// 0xa8
	uint64	cs;						// 0xb0
	uint64	rflags;					// 0xb8
	uint64	rsp;					// 0xc0
	uint64	ss;						// 0xc8
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;

struct syscall_regs
{
	uint64	pad2,pad1;
	struct	regs r;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;

#define	IDT_SIZE	256

#define _SSIZE		((uint16)sizeof(struct gdt_entry))

/* SYSCALL/SYSRET make assumptions as to ordering here */

#define _NULL_CS	(0x00*_SSIZE)	// 0x0

#define	_KERNEL_CS	(0x01*_SSIZE)	// 0x10
#define	_KERNEL_DS	(0x02*_SSIZE)	// 0x08

#define _USER32_DS	(0x03*_SSIZE)	// 0x18
#define _USER32_CS	(0x04*_SSIZE)	// 0x20

#define	_USER_DS	(0x05*_SSIZE)	// 0x28
#define _USER_CS	(0x06*_SSIZE)	// 0x30

#define _TSS_CS		(0x10*_SSIZE)	/* 0x40 - takes up 2 slots */

#define GDT_SIZE	0x20


#define MSR_EFER				0xc0000080
#define MSR_STAR				0xc0000081
#define	MSR_LSTAR				0xc0000082
#define MSR_CSTAR				0xc0000083
#define MSR_SFMASK				0xc0000084
#define MSR_KERNEL_GSBASE		0xc0000102
#define MSR_APIC_BAR			0x0000001b

#define MAX_CPU					32

struct cpu {
	uint8	stepping;
	uint8	model;
	uint8	family;
	uint8	apic_id;
};

struct timeval {
	uint64	tv_sec;
	uint64	tv_usec;
};

// stolen from linux 2.4.31 which inturn was from some other guy

static inline uint64 mktime (uint64 year, uint64 mon, uint64 day, uint64 hour, uint64 min, uint64 sec)
{
	if (0 >= (int) (mon -= 2)) {    /* 1..12 -> 11,12,1..10 */
		mon += 12;              /* Puts Feb last since it has leap day */
		year -= 1;
	}

	return (((
					(unsigned long) (year/4 - year/100 + year/400 + 367*mon/12 + day) +
					year*365 - 719499
			 )*24 + hour /* now have hours */
			)*60 + min /* now have minutes */
		   )*60 + sec; /* finally seconds */
}

static inline void spin_lock(int *lock)
{
	__asm__ __volatile__ (
			"1: lock; cmpxchgl %1, %0; jz 2f; pause; jmp 1b; 2:"
			:
			: "m" (lock), "r" (0)
			);
}

static inline void spun_unloc(uint64 *lock)
{
	*lock = 0;
}

#define PF_P	(1 << 0)
#define	PF_WR	(1 << 1)
#define	PF_US	(1 << 2)
#define	PF_RSVD	(1 << 3)
#define	PF_ID	(1 << 4)

#ifdef _CPU_C
const char *bits_PF[] = {
	"P", "W/R", "U/S", "RSVD", "I/D", NULL
};
#else
extern const char *bits_PF[];
#endif

#include "page.h"

extern struct gdt_entry gdt[GDT_SIZE];
extern struct gdt64_ptr gdtp;
extern struct tss_64 global_tss;
extern struct idt_entry idt[IDT_SIZE];
extern struct idt64_ptr idtp;
extern struct cpu cpus[MAX_CPU];
extern uint8 num_cpus;

void gdt_flush(void);
void idt_flush(void);
void tss_flush(uint16 tsss);
void cr3_flush(pt_t *pml4);
pt_t *get_cr3(void);
void _idt_main(struct regs r);
void idt_main(struct regs *r);
void idt_set_gate(uint8 num, uint64 base, uint16 sel, uint8 type, uint8 ist);
void gdt_set_gate(uint16 num, uint64 base, uint32 limit, uint8 dpl, uint8 flag, uint8 type);
uint64 read_msr(uint32 msr);
void write_msr(uint32 msr, uint64 proc);

#endif
