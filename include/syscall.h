#ifndef _SYSCALL_H
#define _SYSCALL_H

#ifdef _KERNEL
typedef void (* voidfunc)(void);
# include "net.h"

extern voidfunc *syscall_table[];

struct rusage;

extern long  sys_accept(int, struct sockaddr *, socklen_t *) __attribute__((tainted_args));
extern long  sys_access(const char *, int) __attribute__((tainted_args));
extern long  sys_arch_prctl(int, unsigned long) __attribute__((tainted_args));
extern long  sys_bind(int, struct sockaddr *, socklen_t) __attribute__((tainted_args));
extern void *sys_brk(const void *) __attribute__((tainted_args));
extern long  sys_close(int fd) __attribute__((tainted_args));
extern long  sys_creat(const char *, mode_t) __attribute__((tainted_args));
extern long  sys_execve(const char *, char *const *, char *const *) __attribute__((tainted_args));
extern void  sys_exit(int status) __attribute__((tainted_args));
extern void  sys_exit_group(int status) __attribute__((tainted_args));
extern pid_t sys_fork(void) __attribute__((tainted_args));
extern pid_t sys_getpid(void) __attribute__((tainted_args));
extern pid_t sys_getppid(void) __attribute__((tainted_args));
extern pid_t sys_gettid(void) __attribute__((tainted_args));
extern long  sys_ioctl(int, unsigned long, unsigned long) __attribute__((tainted_args));
extern long  sys_kill(pid_t,int) __attribute__((tainted_args));
extern long  sys_listen(int, int) __attribute__((tainted_args));
extern off_t sys_lseek(int, off_t, int) __attribute__((tainted_args));
extern long  sys_mkdir(const char *, mode_t) __attribute__((tainted_args));
extern long  sys_open(const char *, int, mode_t) __attribute__((tainted_args));
extern long  sys_pause(void) __attribute__((tainted_args));
extern ssize_t sys_read(int fd, void *, size_t) __attribute__((tainted_args));
extern long  sys_socket(int, int, int) __attribute__((tainted_args));
extern long  sys_time(time_t *) __attribute__((tainted_args));
extern pid_t sys_wait4(pid_t pid, int *, int options, struct rusage *) __attribute__((tainted_args));
extern ssize_t sys_write(int fd, const void *, size_t) __attribute__((tainted_args));
extern uid_t sys_getuid(void) __attribute__((tainted_args));
extern uid_t sys_getgid(void) __attribute__((tainted_args));
extern uid_t sys_geteuid(void) __attribute__((tainted_args));
extern uid_t sys_getegid(void) __attribute__((tainted_args));
extern pid_t sys_getsid(pid_t) __attribute__((tainted_args));
extern pid_t sys_getpgid(pid_t) __attribute__((tainted_args));
extern pid_t sys_getpgrp(void) __attribute__((tainted_args));
extern pid_t sys_setpgid(pid_t,pid_t) __attribute__((tainted_args));
extern pid_t sys_setsid(void) __attribute__((tainted_args));
extern long  sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize) __attribute__((tainted_args));
extern void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) __attribute__((tainted_args));
extern long  sys_stat(const char *pathname, struct stat *statbuf) __attribute__((tainted_args));
extern long  sys_connect(int sockfs, const struct sockaddr *addr, socklen_t addrlen) __attribute__((tainted_args));
extern mode_t sys_umask(mode_t mask) __attribute__((tainted_args));
extern long  sys_fstat(int fd, struct stat *statbuf) __attribute__((tainted_args));
extern long  sys_mount(const char *src, const char *tgt, const char *fstype, unsigned long flags, const void *data) __attribute__((tainted_args));
extern long  sys_dup(int oldfd) __attribute__((tainted_args));
extern long  sys_chdir(const char *path) __attribute__((tainted_args));
extern long  sys_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) __attribute__((tainted_args));
extern long  sys_nanosleep(struct timespec *req, struct timespec *rem) __attribute__((tainted_args));
extern long  sys_mknod(const char *pathname, mode_t mode, dev_t dev) __attribute__((tainted_args));
extern ssize_t sys_getdents64(int fd, void *dirp, size_t count) __attribute__((tainted_args));
extern char *sys_getcwd(char *bif, size_t size) __attribute__((tainted_args));

extern long sys_unimp(void);

/* syscall.c */
extern void syscall_init(void);

/* intr.S */
extern void sysenter(void);
extern void gousermode(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t)__attribute__((noreturn));

#else
//extern unsigned long _dosyscall(unsigned long,unsigned long,unsigned long,unsigned long,unsigned long,unsigned long);
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
#define SYSCALL_STAT    4
#define SYSCALL_FSTAT   5

#define SYSCALL_LSEEK   8
#define SYSCALL_MMAP    9

#define SYSCALL_BRK		12

#define SYSCALL_SIGACTION   13
#define SYSCALL_SIGPROCMASK 14
#define SYSCALL_SIGRETURN   15

#define SYSCALL_IOCTL	16

#define SYSCALL_ACCESS  21

#define SYSCALL_DUP		32

#define SYSCALL_PAUSE	34
#define SYSCALL_NANOSLEEP 35

#define	SYSCALL_GETPID	39

#define	SYSCALL_SOCKET	41

#define SYSCALL_CONNECT 42
#define SYSCALL_ACCEPT	43
#define SYSCALL_BIND	49
#define SYSCALL_LISTEN	50

#define SYSCALL_FORK	57

#define	SYSCALL_EXECVE	59
#define	SYSCALL_EXIT	60
#define	SYSCALL_WAIT4	61
#define	SYSCALL_KILL	62

#define SYSCALL_GETCWD  79
#define SYSCALL_CHDIR   80

#define SYSCALL_MKDIR	83

#define SYSCALL_CREAT	85

#define SYSCALL_UMASK   95

#define SYSCALL_KLUDGE	100

#define SYSCALL_GETUID  102

#define SYSCALL_GETGID  104

#define SYSCALL_GETEUID 107
#define SYSCALL_GETEGID 108

#define SYSCALL_SETPGID 109
#define SYSCALL_GETPPID 110
#define SYSCALL_GETPGRP 111
#define SYSCALL_SETSID  112

#define SYSCALL_GETPGID 121

#define SYSCALL_GETSID  124

#define SYSCALL_MKNOD   133

#define SYSCALL_ARCH_PRCTL 158

#define SYSCALL_MOUNT   165

#define SYSCALL_GETTID	186

#define SYSCALL_TIME	201

#define SYSCALL_GETDENTS64 217

#define SYSCALL_EXIT_GROUP 231

#define MAX_SYSCALL		1024

#endif


