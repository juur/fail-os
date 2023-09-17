#ifndef _KTYPES_H
#define _KTYPES_H
#define _Unused __attribute__((unused))

#include <errno.h>

typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int 	uint32_t;
typedef unsigned long 	uint64_t;
typedef	char			int8_t;
typedef	short			int16_t;
typedef	int				int32_t;
typedef long			int64_t;
typedef unsigned long   uintptr_t;

/* sync with fail-libc/sys/types.h */

typedef int           clock_t;
typedef int           clockid_t;
typedef int           pid_t;
typedef int           wchar_t;
typedef long          blksize_t;
typedef long          off_t;
typedef long          ssize_t;
typedef long          suseconds_t;
typedef long          time_t;
typedef unsigned      gid_t;
typedef unsigned      mode_t;
typedef unsigned      uid_t;
typedef unsigned int  dev_t;
typedef unsigned int  socklen_t;
typedef unsigned long blkcnt_t;
typedef unsigned long ino_t;
typedef unsigned long nlink_t;
typedef          long ptrdiff_t;
typedef unsigned long size_t;
typedef void *        timer_t;
typedef unsigned long sigset_t;

typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

#define NULL ((void*)0)

#define IS_ERR(x) ((x) > ~0xff)
#define GET_ERR(x) ((x) & 0xff)

#define BIT_INDEX(a) ((a)/64UL)
#define BIT_OFFSET(a) (63UL-((a)%64UL))
// FIXME: this was 31- but that broken n=1 frame operatons, but now it's not, it's probably broken n>1 frame operations

typedef _Bool bool;
#define true 1
#define false 0

#define SECOND_COMP(x)	((~(x))+1)

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))
#define EPERM        1
#define ENOENT       2
#define ESRCH        3
#define EINTR        4
#define EIO          5
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

#define EDEADLK		35
#define ENAMETOOLONG 36
#define ENOLCK		37
#define ENOSYS		38
#define ENOTEMPTY	39
#define ELOOP		40
#define ENOMSG		42


#endif
