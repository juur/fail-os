#ifndef _PROC_H
#define _PROC_H

#include "klibc.h"
#include "cpu.h"
#include "page.h"

#define NUM_TASKS	10
#define STACK_SIZE	4096
#define BIG_PAGE_SIZE	0x400000

extern uint64 curtask;

struct tss_64 {
	unsigned int	res0;

	unsigned long	rsp0;
	unsigned long	rsp1;
	unsigned long	rsp2;

	unsigned long	res1;

	unsigned long	ist1;
	unsigned long	ist2;
	unsigned long	ist3;
	unsigned long	ist4;
	unsigned long	ist5;
	unsigned long	ist6;
	unsigned long	ist7;

	unsigned long	res2;
	unsigned long	res3;

	unsigned short	res4;
	unsigned short	io_map_base_addr;

	unsigned char	io_perm_bitmap[0x2000];
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;
#define	MAX_FD			0x10

struct task {
	struct regs tss;				// 0x00
	char	*stacksave;				// 0xd0
	uint8	*kernelsptr;			// 0xd8
	struct task *this_task;			// 0xe0
	uint64	rip;					// 0xe8
	uint64	rflags;					// 0xf0
	uint64	newpid;
	uint8	*kernelstack;
	pt_t 	*pd;
	uint64	state;
	uint8	*data_start;
	uint8	*data_end;
	uint8	*code_start;
	uint8	*code_end;
	uint8	*stack_start;		// bottom of the stack
	uint8	*stack_end;			// top of the stack
	uint8	*heap_start;
	uint8	*heap_end;
	char	name[256];
	struct fileh	*fps[MAX_FD];
	struct elf	*elf;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
;
#define STATE_EMPTY		0
#define	STATE_KILLING	1
#define STATE_CREATING	2
#define STATE_RUNNING	3
#define STATE_WAIT		4
#define	STATE_EXECVE	5
#define	STATE_FORK		6
#define STATE_NUM		7

extern const char *state_names[STATE_NUM];

#define USER_STACK_START    (1024*1024*1024)
#define USER_STACK_SIZE     (0x4 * PAGE_SIZE)
#define USER_CODE_START     (USER_STACK_START+USER_STACK_SIZE)

#define USER_START          USER_STACK_START
#define USER_RSP            (USER_STACK_START+USER_STACK_SIZE-0x8)

#define USER_TASK		0x0
#define KERNEL_TASK		0x1
#define	CLONE_TASK		0x2

extern struct task tasks[NUM_TASKS];

struct rusage {
	uint64	crap;
};

void sched_fail(void);
void print_tasks(void);
void print_task(struct task *tsk);
void lock_tasks(void);
void unlock_tasks(void);
uint64 find_free_task(bool lock);
void *add_page_task(struct task *tsk);
void sched_main( struct regs *r);
void setup_task(struct task *tsk, uint64 eip, int type, pt_t *pd, const char *name, uint64 user_esp);
uint64 do_exec(struct task *t, const char *f, uint8 **code, uint64 *clen, uint8 **data, uint64 *dlen, uint64 *vaddr, uint64 *daddr);
struct task *get_task(uint64 i);
void print_reg(struct regs *r);
void dump_task(struct task *t);
void do_fork(struct task *ctask, struct regs *r, uint64 rip,
		        uint64 rsp, uint64 rflags);

#endif
