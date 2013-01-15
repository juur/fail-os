#include "klibc.h"
#include "cpu.h"
#include "proc.h"
#include "syscall.h"

uint64 syscall_table[MAX_SYSCALL];

/* FIXME how to make this actually stop ? */

uint64 sys_pause()
{
//	printf("task[%x] sys_pause()\n", curtask);
	lock_tasks();
	tasks[curtask].state = STATE_WAIT;
	unlock_tasks();
	return 0;
}

uint64 sys_kill(uint64 pid, uint64 sig)
{
	struct task *t;
	uint64 ret = (uint64)-1;

	lock_tasks();
	if(!(t=get_task(pid))) goto end;

	if(t->state == STATE_WAIT) {
		t->state = STATE_RUNNING;
	}

	ret = 0;

end:
	unlock_tasks();
	return ret;
}


uint64 sys_unimp(uint64 a, uint64 b, uint64 c, uint64 d, uint64 e)
{
	printf("task[%x] Unimplemented syscall: args: %lx,%lx,%lx,%lx,%lx\n",curtask,a,b,c,d,e);

	return 0;
}

/*void sysenter_main(struct task *t, struct regs r)
{
	uint64 syscall = r.rax;
	uint64 ret = -ENOSYS;

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

struct sys_call_regs
{
	struct regs r;
	long	rcx;
	long	r11;
};

uint64 sys_getpid(void)
{
	//long rsp;
/*
	__asm__ ( 
			"movq %%rsp, %[a1] ;"
			:
			[a1] "=m" (rsp)
	   );

	printf("sys_getpid: %x, %x ,%x\n", curtask, rsp, tasks[curtask].stacksave);*/
	return curtask;
}

uint8 *sys_brk(uint8 *brk)
{
	struct task *ctsk = &tasks[curtask];
	if(brk < ctsk->heap_end) goto out;
	if(brk >= ctsk->heap_start + 0x1000000) goto out;
	ctsk->heap_end = (uint8 *)brk;
out:
	//dump_task(ctsk);
	return ctsk->heap_end;
}
