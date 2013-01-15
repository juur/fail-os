#undef _KERNEL
#ifndef _LIBC_H
#define _LIBC_H
#define va_list __builtin_va_list
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

#ifdef __cplusplus
	#define NULL 0
#else
	typedef enum { false, true } bool;
	#define NULL ((void*)0)
#endif

typedef struct {
	int fd;
} FILE;

typedef unsigned long	size_t;
typedef long			ssize_t;
typedef	int				pid_t;

#define EOF (-1)


#define EPERM        1
#define ENOENT       2
#define ESRCH        3
#define EINTR        4
#define EIO      	 5  
#define ENXIO        6
#define E2BIG        7
#define ENOEXEC      8
#define EBADF        9
#define ECHILD      10
#define EAGAIN      11
#define ENOMEM      12
#define EACCES      13
#define EFAULT      14
#define ENOTBLK     15
#define EBUSY       16
#define EEXIST      17
#define EXDEV       18
#define ENODEV      19
#define ENOTDIR     20
#define EISDIR      21
#define EINVAL      22
#define ENFILE      23
#define EMFILE      24
#define ENOTTY      25
#define ETXTBSY     26
#define EFBIG       27
#define ENOSPC      28
#define ESPIPE      29
#define EROFS       30
#define EMLINK      31
#define EPIPE       32
#define EDOM        33
#define ERANGE      34

#define O_RDONLY	0x0
#define	O_WRONLY	0x1
#define	O_RDWR		0x2

#define	EXIT_SUCCESS	0

struct rusage;

void exit(int status);
void printf(const char *format, ...);
int putchar(int c);
int getchar(void);
int brk(void *addr);
int open(const char *pathname, int flags);
pid_t fork(void);
pid_t wait(int *status);
int execvp(const char *file, char *const argv[]);
pid_t getpid(void);

#include "syscall.h"

#define SYSCALL0(sc)	 	_dosyscall(sc,0,0,0,0,0)
#define SYSCALL1(sc,a)	 	_dosyscall(sc,(unsigned long)(a),0,0,0,0)
#define SYSCALL2(sc,a,b) 	_dosyscall(sc,(unsigned long)(a),(unsigned long)(b),0,0,0)
#define SYSCALL3(sc,a,b,c)	_dosyscall(sc,(unsigned long)(a),(unsigned long)(b),(unsigned long)(c),0,0)
#define SYSCALL4(sc,a,b,c,d)	_dosyscall(sc,(unsigned long)(a),(unsigned long)(b),(unsigned long)(c),(unsigned long)(d),0)

#endif
