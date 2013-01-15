#ifndef _SYSCALL_H
#define _SYSCALL_H

#ifdef _KERNEL

#include "net.h"

extern uint64 syscall_table[];

struct rusage;

uint64 sys_unimp(uint64 a, uint64 b, uint64 c, uint64 d, uint64 e);
uint64 sys_pause();
uint64 sys_kill(uint64,uint64);
uint64 sys_time(void *);
uint64 sys_open(char *name);
uint64 sys_write(uint64 fd, uint8 *data, uint64 len);
uint64 sys_getpid();
uint64 sys_close(uint64 fd);
uint64 sys_read(uint64 fd, uint8 *data, uint64 len);
uint64 sys_fork(void);
uint8 *sys_brk(uint8 *);
uint64 sys_bind(uint64, struct sockaddr *, uint64);
uint64 sys_accept(uint64, struct sockaddr *, uint64 *);
uint64 sys_listen(uint64, uint64);
uint64 sys_socket(uint64 family, uint64 type, uint64 protocol);
uint64 sys_execve(const char *file, char *const argv[], char *const envp[]);
uint64 sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage);
void sys_exit(int status);

#else
unsigned long _dosyscall(unsigned long,unsigned long,unsigned long,unsigned long,
		unsigned long,unsigned long);
#endif

/* we aim to be vaguely compatable with the Linux API/ABI
 * but not behavour identical
 */

#define	SYSCALL_READ	0
#define SYSCALL_WRITE	1
#define	SYSCALL_OPEN	2
#define	SYSCALL_CLOSE	3

#define SYSCALL_BRK		12

#define SYSCALL_IOCTL	16

#define SYSCALL_PAUSE	34

#define	SYSCALL_GETPID	39

#define	SYSCALL_SOCKET	41

#define SYSCALL_ACCEPT	43
#define SYSCALL_BIND	49
#define SYSCALL_LISTEN	50

#define SYSCALL_FORK	57

#define	SYSCALL_EXECVE	59
#define	SYSCALL_EXIT	60
#define	SYSCALL_WAIT4	61
#define	SYSCALL_KILL	62

#define SYSCALL_TIME	201

#define MAX_SYSCALL		0x100

#endif


