#ifndef _SYSCALL_H
#define _SYSCALL_H

#ifdef _KERNEL
typedef void (* voidfunc)(void);
# include "net.h"

# ifndef _SYSCALL_C
extern voidfunc *syscall_table[];
# endif

struct rusage;

int   sys_accept(int, struct sockaddr *, socklen_t *);
int   sys_arch_prctl(int, unsigned long);
int   sys_bind(int, struct sockaddr *, socklen_t);
long  sys_brk(void *);
int   sys_close(int fd);
int   sys_creat(const char *, mode_t);
int   sys_execve(const char *, const char *const *, const char *const *);
void  sys_exit(int status);
void  sys_exit_group(int status);
pid_t sys_fork(void);
pid_t sys_getpid(void);
pid_t sys_getppid(void);
pid_t sys_gettid(void);
long  sys_ioctl(unsigned int, unsigned int, unsigned long);
long  sys_kill(pid_t,int);
int   sys_listen(int, int);
off_t sys_lseek(int, off_t, int);
int   sys_mkdir(const char *, mode_t);
int   sys_open(const char *, int, mode_t);
long  sys_pause(void);
ssize_t sys_read(int fd, void *, size_t);
int   sys_socket(int, int, int);
long  sys_time(time_t *);
pid_t sys_wait4(pid_t pid, int *, int options, struct rusage *);
ssize_t sys_write(int fd, const void *, size_t);
uid_t sys_getuid(void);
uid_t sys_getgid(void);
uid_t sys_geteuid(void);
uid_t sys_getegid(void);

long sys_unimp(void);

#else
extern unsigned long _dosyscall(unsigned long,unsigned long,unsigned long,unsigned long,unsigned long,unsigned long);
#endif

#define ARCH_SET_GS	0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

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

#define SYSCALL_MKDIR	83

#define SYSCALL_CREAT	85

#define SYSCALL_KLUDGE	100

#define SYSCALL_GETUID  102

#define SYSCALL_GETGID  104

#define SYSCALL_GETEUID 107
#define SYSCALL_GETEGID 108

#define SYSCALL_GETPPID 110

#define SYSCALL_ARCH_PRCTL 158

#define SYSCALL_GETTID	186

#define SYSCALL_TIME	201

#define SYSCALL_EXIT_GROUP 231

#define MAX_SYSCALL		232

#endif


