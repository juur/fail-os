#ifndef _PROC_H
#define _PROC_H

#include <ktypes.h>
#include <cpu.h>
#include <page.h>

#define NUM_TASKS	20
// was 4096
#define STACK_SIZE		(PGSIZE_4K * 16U)

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

#define	MAX_FD			0x100

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
	pid_t    sid;
	pid_t    pgid;
	uid_t	 uid;
	uid_t	 euid;
	gid_t	 gid;
	gid_t	 egid;
	mode_t   umask;
    int      lock;
	char	 name[256];

	struct fileh	*fps[MAX_FD];
	struct elf		*elf;
	struct iname    *cwd;
	sigset_t         sigset;
	void            *cr3_save;
	struct timeval   sleep_till;
    pid_t wait4_pid;
    pid_t wait4_watcher;

	uint64_t pad1 __attribute__((aligned (16))); /* it explodes if struct is not aligned */
} __attribute__((packed));

#define STATE_EMPTY		0
#define	STATE_KILLING	1
#define STATE_CREATING	2
#define STATE_RUNNING	3
#define STATE_WAIT		4
#define	STATE_EXECVE	5
#define	STATE_FORK		6
#define STATE_SLEEP     7
#define STATE_ZOMBIE    8
#define STATE_NUM		9

#define USER_TASK		0x0
#define KERNEL_TASK		0x1
#define	CLONE_TASK		0x2

extern struct task tasks[NUM_TASKS];
extern unsigned long tick;
extern long curtask;
extern pid_t firsttask;

struct rusage {
	uint64_t	crap;
};

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20

/* fail-libc/include/sys/wait.h */

#define WNOHANG    1
#define WNOTRACE   2
#define WEXITED    4
#define WCONTINUED 8

/* fail-libc/include/signal.h */

#define SIGHUP   1
#define SIGINT   2
#define SIGQUIT  3
#define SIGILL   4
#define SIGTRAP  5
#define SIGABRT  6
#define SIGBUS   7
#define SIGFPE   8
#define SIGKILL  9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG  23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGPOLL 29
#define SIGPWR 30
#define SIGSYS 31
#define NSIG 64

typedef void (*__sighandler_t)(int);

#define SIG_ERR ((__sighandler_t)-1)
#define SIG_DFL ((__sighandler_t)0)
#define SIG_IGN ((__sighandler_t)1)

union sigval {
    int    sival_int;
    void  *sival_ptr;
};

typedef struct {
    int           si_signo;
    int           si_code;
    int           si_errno;
    pid_t         si_pid;
    uid_t         si_uid;
    void         *si_addr;
    int           si_status;
    long          si_band;
    union sigval  si_value;
} siginfo_t;

struct sigaction {
    void   (*sa_handler)(int);
    sigset_t sa_mask;
    int      sa_flags;
    void   (*sa_sigaction)(int, siginfo_t *, void *);
};

static inline struct task *get_current_task() {
    return &tasks[curtask];
}

extern void         sched_fail(void);
extern void         _lock_tasks(const char *, const char *, int);
extern void         _unlock_tasks(const char *, const char *, int);
extern pid_t        find_free_task(bool lock);
extern void        *add_page_task(struct task *tsk)__attribute__((nonnull));
extern void         sched_main(volatile struct regs *r)__attribute__((nonnull));
extern long         setup_task(struct task *tsk, uint64_t rip, int type, pt_t *pd, const char *name, uint64_t user_rsp, pid_t pid) __attribute__((nonnull(1,4)));
extern struct task *get_task(pid_t i);
extern int          set_task_state(struct task *task, int new_state) __attribute__((nonnull));
extern void         clean_task(struct task * tsk) __attribute__((nonnull));

//extern long  do_exec(struct task *task, const char *filename, uint8_t **code, size_t *code_len, uint8_t **data, size_t *data_len, uint64_t *virt_addr, uint64_t *data_addr, void **) __attribute__((nonnull, access(read_only, 2)));

extern void  dump_tasks();
extern void  print_tasks(void);
extern void  print_task(const struct task *)__attribute__((nonnull));

#define lock_tasks() _lock_tasks(__FILE__,__func__,__LINE__)
#define unlock_tasks() _unlock_tasks(__FILE__,__func__,__LINE__)

#endif
// vim: set ft=c:
