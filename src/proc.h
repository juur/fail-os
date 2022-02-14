#ifndef _PROC_H
#define _PROC_H

#include "klibc.h"
#include "cpu.h"
#include "page.h"

#define NUM_TASKS	10
// was 4096
#define STACK_SIZE		(PGSIZE_4K * 16)
#define BIG_PAGE_SIZE	0x400000

extern uint64_t curtask;

struct tss_64 {
	uint32_t	res0;

	uint64_t	rsp0;
	uint64_t	rsp1;
	uint64_t	rsp2;

	uint64_t	res1;

	uint64_t	ist1;
	uint64_t	ist2;
	uint64_t	ist3;
	uint64_t	ist4;
	uint64_t	ist5;
	uint64_t	ist6;
	uint64_t	ist7;

	uint64_t	res2;

	uint16_t	res4;
	uint16_t	io_map_base_addr;

	uint8_t		io_perm_bitmap[0x2000];
} __attribute__((packed));

#define	MAX_FD			0x10

struct task {
	/* START do not change order see intr.S:sysenter */

		struct regs tss;					// 0x00

		/* syscall: user saved RSP */
		void	*stacksave;					// 0xd0

		/* syscall: kernel saved RSP */
		void	*kernelsptr;				// 0xd8
	
		struct task *this_task;				// 0xe0

		/* syscall saved RIP and RFLAGS */
		uint64_t	syscall_rip;			// 0xe8
		uint64_t	syscall_rflags;			// 0xf0

		uint64_t	pad0;					// 0xf8

		uint8_t		xsave[512];				// 0x100 - must be aligned

	/* END */

	void	*kernelstack;
	pt_t	*pd;
	int		 state;
	
	void    *tls;
	void	*gsbase;
	void	*kerngsbase;

	void	*data_start;
	void	*data_end;
	void	*code_start;
	void	*code_end;
	void	*stack_start;		// bottom of the stack
	void	*stack_end;			// top of the stack
	void	*heap_start;
	void	*heap_end;

	int		 exit_status;
	pid_t	 pid;
	pid_t	 ppid;
	uid_t	 uid;
	uid_t	 euid;
	gid_t	 gid;
	gid_t	 egid;
	char	 name[256];

	struct fileh	*fps[MAX_FD];
	struct elf		*elf;
	struct iname    *cwd;

	uint64_t pad1 __attribute__((aligned (16))); /* it explodes if struct is not aligned */
} __attribute__((packed))
;
#define STATE_EMPTY		0
#define	STATE_KILLING	1
#define STATE_CREATING	2
#define STATE_RUNNING	3
#define STATE_WAIT		4
#define	STATE_EXECVE	5
#define	STATE_FORK		6
#define STATE_NUM		7

//extern const char *state_names[STATE_NUM];

/* wtf does this do? */
#define USER_STACK_START    (1024*1024*1024)
//#define USER_STACK_SIZE     (0x4 * PAGE_SIZE)
//#define USER_CODE_START     (USER_STACK_START+USER_STACK_SIZE)

//#define USER_START          USER_STACK_START
//#define USER_RSP            (USER_STACK_START+USER_STACK_SIZE-0x8)

#define USER_TASK		0x0
#define KERNEL_TASK		0x1
#define	CLONE_TASK		0x2

extern struct task tasks[NUM_TASKS];

struct rusage {
	uint64_t	crap;
};

void sched_fail(void);
void print_tasks(void);
void print_task(const struct task *restrict)__attribute__((nonnull));
void lock_tasks(void);
void unlock_tasks(void);
uint64_t find_free_task(bool lock);
void *add_page_task(struct task *tsk);
void sched_main(volatile struct regs *r)__attribute__((nonnull));
void setup_task(struct task *tsk, uint64_t rip, int type, const pt_t *pd, const char *name, uint64_t user_rsp, int pid)__attribute__((nonnull(1,4)));
long do_exec(struct task *t, const char *f, uint8_t **code, uint64_t *clen, uint8_t **data, uint64_t *dlen, uint64_t *vaddr, uint64_t *daddr)__attribute__((nonnull));
struct task *get_task(uint64_t i);
//void dump_task(struct task *t);
void dump_tasks();

#endif
// vim: set ft=c:
