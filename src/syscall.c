#define _SYSCALL_C
#ifndef _KERNEL
# define _KERNEL
#endif
#include "klibc.h"
#include "cpu.h"
#include "proc.h"
#include "syscall.h"

voidfunc sc_tbl[MAX_SYSCALL];

/* FIXME how to make this actually stop ? */

long sys_pause()
{
//	printf("task[%x] sys_pause()\n", curtask);
	lock_tasks();
	tasks[curtask].state = STATE_WAIT;
	unlock_tasks();
	return 0;
}

long sys_kill(const pid_t pid, const int sig)
{
	struct task *t;
	uint64_t ret = (uint64_t)-1;

	lock_tasks();
	if((t = get_task(pid)) == NULL) goto end;

	if(t->state == STATE_WAIT) {
		t->state = STATE_RUNNING;
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
	/* FIXME */
	return curtask;
}

pid_t sys_getppid(void)
{
	return tasks[curtask].ppid;
}

pid_t sys_getpid(void)
{
	//long rsp;
/*
	__asm__ ( 
			"movq %%rsp, %[a1] ;"
			:
			[a1] "=m" (rsp)
	   );*/

	//printf("sys_getpid: %lx\n", curtask);
	return curtask;
}

void *do_brk(struct task *const t, const void *const brk)
{
	void *ret = (void *)-ENOMEM;

	if(brk == NULL) {
		ret = t->heap_end;
		goto out;
	}
	if(brk < t->heap_end) goto out;
	if(brk >= (void *)((uint64_t)t->heap_start + 0x1000000)) goto out;

	ret = t->heap_end = (void *)brk;
out:
	return ret;

}

long sys_brk(void *const brk)
{
	struct task *const ctsk = &tasks[curtask];
	return (int64_t)do_brk(ctsk, brk);
}

long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	printf("sys_ioctl: %x, %x, %lx\n", fd, cmd, arg);
	return 0;
}

long sys_kludge()
{
	//dump_fsents();
	return 0;
}

int sys_arch_prctl(int code, unsigned long addr)
{
	struct task *t = &tasks[curtask];

	switch(code)
	{
		case ARCH_SET_FS:
			write_msr(MSR_FSBASE, addr);
			t->tls = (uint8_t *)addr;
			//printf("arch_prctl: setting FSBASE to %lx\n", addr);
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

	printf("done\n");
}
