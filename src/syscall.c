#include <klibc.h>
#include <cpu.h>
#include <proc.h>
#include <syscall.h>

voidfunc sc_tbl[MAX_SYSCALL];

/* FIXME how to make this actually stop ? */

long sys_pause()
{
//	printf("task[%x] sys_pause()\n", curtask);
	//printf("sys_pause\n");
	lock_tasks();
	set_task_state(get_current_task(), STATE_WAIT);
	unlock_tasks();
	return 0;
}

long sys_nanosleep(struct timespec *req, struct timespec *rem)
{
	if (req->tv_nsec < 0 || req->tv_nsec > 999999999 || req->tv_sec <= 0)
		return -EINVAL;

	extern struct timeval kerntime;
	struct task *ctsk = get_current_task();

	ctsk->sleep_till.tv_sec = kerntime.tv_sec + req->tv_sec;
	set_task_state(ctsk, STATE_SLEEP);

	while (ctsk->state == STATE_SLEEP && kerntime.tv_sec < ctsk->sleep_till.tv_sec) {
		sti();
		//printf("sys_nanosleep: check\n");
		hlt();
		//pause();
	}
	cli();

	return -EINTR;
}

long sys_kill(const pid_t pid, const int sig)
{
	struct task *t;
	uint64_t ret = (uint64_t)-1;
	//printf("sys_kill\n");

	lock_tasks();
	if((t = get_task(pid)) == NULL) goto end;
	/* FIXME security */

	if(t->state == STATE_WAIT) {
		set_task_state(t, STATE_RUNNING);
	}

	ret = sig - sig;

end:
	unlock_tasks();
	return ret;
}


long sys_unimp(void)
{
	uint64_t num = 0;
	__asm__ volatile ( "mov %%rax, %0" :: "m"(num) );
	printf("sys_unimp: %ld\n", num);
	return -ENOSYS;
}

/*void sysenter_main(struct task *t, struct regs r)
{
	uint64_t syscall = r.rax;
	uint64_t ret = -ENOSYS;

	if(r.cs == _KERNEL_CS) {
		printf("syscall: error trying to use syscall from KERNEL_CS\n");
		r.rax = ret;
		return;
	}

	switch(syscall) 
	{
		case SYSCALL_GETPID:
			ret = sys_getpid();
			break;
		default:
			break;
	}

	r.rax = ret;
	return;
}
*/

/*
struct sys_call_regs
{
	struct regs r;
	long	rcx;
	long	r11;
};
*/

pid_t sys_gettid(void)
{
	//printf("sys_gettid\n");
	//dump_pools();
	/* FIXME */
	return get_current_task()->pid;
}

pid_t sys_getppid(void)
{
	//printf("sys_getppid\n");
	return get_current_task()->ppid;
}

pid_t sys_getpid(void)
{
	//printf("sys_getpid\n");
	return curtask;
}

__attribute__((nonnull(1)))
void *do_brk(struct task *const t, const void *const brk)
{
	//printf("do_brk: brk=%p\n", brk);

	if(brk == 0) {
		return t->heap_end;
	} else if(brk <= t->heap_start) {
		printf("do_brk: attempt to set brk to before heap_start for pid=%d [%p < %p]\n", 
				t->pid, brk, t->heap_start);
	} else if (brk < t->heap_end) {
		printf("do_brk: shrinking heap is unsupported for pid=%d\n", t->pid);
	} else if(brk >= (void *)((uint64_t)t->heap_start + 0x1000000)) {
		printf("do_brk: attempt to request too much memory for pid=%d [0x%08lx > 0x%08lx] [heap:%p, stack:%p, code:%p]\n", 
				t->pid, (uint64_t)brk, ((uint64_t)t->heap_start) + 0x1000000,
				t->heap_start, t->stack_start, t->code_start);
	} else {
		t->heap_end = (void *)brk;
	}
	return t->heap_end;
}

long sys_kludge(long arg)
{
	return arg;
}

long sys_arch_prctl(int code, unsigned long addr)
{
	struct task *t = get_current_task();

	switch(code)
	{
		case ARCH_SET_FS:
			write_msr(MSR_FSBASE, addr);
			t->tls = (uint8_t *)addr;
			return 0;
		case ARCH_GET_FS:
			*(unsigned long *)addr = (uint64_t)t->tls;
			return 0;
		default:
			return -EINVAL;
	}
}

void syscall_init(void)
{
	printf("syscall_init: ");

	for(int i=0; i<MAX_SYSCALL; i++)
		sc_tbl[i] = (voidfunc)sys_unimp;

	sc_tbl[SYSCALL_ACCEPT]     = (voidfunc)sys_accept;
	sc_tbl[SYSCALL_ACCESS]     = (voidfunc)sys_access;
	sc_tbl[SYSCALL_ARCH_PRCTL] = (voidfunc)sys_arch_prctl;
	sc_tbl[SYSCALL_BIND]       = (voidfunc)sys_bind;
	sc_tbl[SYSCALL_BRK]        = (voidfunc)sys_brk;
	sc_tbl[SYSCALL_CLOSE]      = (voidfunc)sys_close;
	sc_tbl[SYSCALL_CREAT]      = (voidfunc)sys_creat;
	sc_tbl[SYSCALL_EXECVE]     = (voidfunc)sys_execve;
	sc_tbl[SYSCALL_EXIT]       = (voidfunc)sys_exit;
	sc_tbl[SYSCALL_EXIT_GROUP] = (voidfunc)sys_exit_group;
	sc_tbl[SYSCALL_FORK]       = (voidfunc)sys_fork;
	sc_tbl[SYSCALL_GETEGID]    = (voidfunc)sys_getegid;
	sc_tbl[SYSCALL_GETEUID]    = (voidfunc)sys_geteuid;
	sc_tbl[SYSCALL_GETGID]     = (voidfunc)sys_getgid;
	sc_tbl[SYSCALL_GETPID]     = (voidfunc)sys_getpid;
	sc_tbl[SYSCALL_GETPPID]    = (voidfunc)sys_getppid;
	sc_tbl[SYSCALL_GETTID]     = (voidfunc)sys_gettid;
	sc_tbl[SYSCALL_GETUID]     = (voidfunc)sys_getuid;
	sc_tbl[SYSCALL_IOCTL]      = (voidfunc)sys_ioctl;
	sc_tbl[SYSCALL_KILL]       = (voidfunc)sys_kill;
	sc_tbl[SYSCALL_KLUDGE]     = (voidfunc)sys_kludge;
	sc_tbl[SYSCALL_LISTEN]     = (voidfunc)sys_listen;
    sc_tbl[SYSCALL_MKDIR]      = (voidfunc)sys_mkdir;
	sc_tbl[SYSCALL_OPEN]       = (voidfunc)sys_open;
	sc_tbl[SYSCALL_PAUSE]      = (voidfunc)sys_pause;
	sc_tbl[SYSCALL_READ]       = (voidfunc)sys_read;
	sc_tbl[SYSCALL_SOCKET]     = (voidfunc)sys_socket;
	sc_tbl[SYSCALL_TIME]       = (voidfunc)sys_time;
	sc_tbl[SYSCALL_WAIT4]      = (voidfunc)sys_wait4;
	sc_tbl[SYSCALL_WRITE]      = (voidfunc)sys_write;
	sc_tbl[SYSCALL_GETSID]     = (voidfunc)sys_getsid;
	sc_tbl[SYSCALL_GETPGID]    = (voidfunc)sys_getpgid;
	sc_tbl[SYSCALL_GETPGRP]    = (voidfunc)sys_getpgrp;
	sc_tbl[SYSCALL_SETSID]     = (voidfunc)sys_setsid;
	sc_tbl[SYSCALL_SETPGID]    = (voidfunc)sys_setpgid;
	sc_tbl[SYSCALL_SIGPROCMASK]= (voidfunc)sys_sigprocmask;
	sc_tbl[SYSCALL_MMAP]       = (voidfunc)sys_mmap;
	sc_tbl[SYSCALL_STAT]       = (voidfunc)sys_stat;
	sc_tbl[SYSCALL_CONNECT]    = (voidfunc)sys_connect;
	sc_tbl[SYSCALL_UMASK]      = (voidfunc)sys_umask;
	sc_tbl[SYSCALL_MOUNT]      = (voidfunc)sys_mount;
	sc_tbl[SYSCALL_DUP]        = (voidfunc)sys_dup;
	sc_tbl[SYSCALL_CHDIR]      = (voidfunc)sys_chdir;
	sc_tbl[SYSCALL_SIGACTION]  = (voidfunc)sys_sigaction;
	sc_tbl[SYSCALL_NANOSLEEP]  = (voidfunc)sys_nanosleep;
	sc_tbl[SYSCALL_MKNOD]      = (voidfunc)sys_mknod;
	sc_tbl[SYSCALL_FSTAT]      = (voidfunc)sys_fstat;
	sc_tbl[SYSCALL_GETDENTS64] = (voidfunc)sys_getdents64;
    sc_tbl[SYSCALL_GETCWD]     = (voidfunc)sys_getcwd;
    sc_tbl[SYSCALL_LSEEK]      = (voidfunc)sys_lseek;

    int sc_count = 0;

    for(int i = 0; i < MAX_SYSCALL; i++)
        if (sc_tbl[i] != (voidfunc)sys_unimp)
            sc_count++;

	printf("%d system calls implemented\n", sc_count);
}
