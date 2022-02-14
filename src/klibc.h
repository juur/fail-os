#ifndef _KLIBC_H
#define _KLIBC_H

//#ifdef  _KERNEL
#define noreturn _Noreturn
#define _Unused __attribute__((unused))
//#endif

#include "errno.h"

typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int 	uint32_t;
typedef unsigned long 	uint64_t;
typedef	unsigned long	size_t;
typedef long			ssize_t;
typedef	char			int8_t;
typedef	short			int16_t;
typedef	int				int32_t;
typedef long			int64_t;
typedef long			time_t;
typedef int				pid_t;
typedef long			off_t;
//typedef unsigned short	umode_t;
typedef unsigned int    dev_t;
typedef long			ino_t;
typedef unsigned        mode_t;
typedef unsigned long   nlink_t;
typedef unsigned		uid_t;
typedef unsigned		gid_t;
typedef long			blksize_t;
typedef unsigned long	blkcnt_t;
typedef unsigned int    socklen_t;

typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

#define NULL ((void*)0)

#define BIT_INDEX(a) ((a)/64)
#define BIT_OFFSET(a) (63-((a)%64)) 
// FIXME: this was 31- but that broken n=1 frame operatons, but now it's not, it's probably broken n>1 frame operations

typedef _Bool bool;
#define true 1
#define false 0

#define SECOND_COMP(x)	((~(x))+1)

void print_bits(uint64_t val, const char *bits[], uint64_t max, uint8_t br)__attribute__((nonnull));
int putsn(const char *text, size_t max)__attribute__((nonnull));
int puts(const char *text)__attribute__((nonnull));
int printf(const char *format, ...) __attribute__((__format__ (__printf__, 1, 2),nonnull(1)));
void *memcpy(void *dest, const void *src, size_t count)__attribute__((nonnull));
void *memset(void *dest, int val, size_t count)__attribute__((nonnull));
uint16_t *memsetw(uint16_t *dest, unsigned short val, size_t count)__attribute__((nonnull));
char *strcpy(char *dest, const char *source)__attribute__((nonnull));
char *strncpy(char *dest, const char *source, size_t count)__attribute__((nonnull));
size_t strlen(const char *str)__attribute__((nonnull));
size_t strnlen(const char *str, size_t)__attribute__((nonnull));
int popcountll(unsigned long long x);
int strcmp(const char *a, const char *b)__attribute__((nonnull));
char *strdup(const char *s)__attribute__((nonnull));
int strncmp(const char *a, const char *b, size_t len)__attribute__((nonnull));
int isprint(int);
char *dirname(const char *path)__attribute__((nonnull));
char *basename(const char *path)__attribute__((nonnull));
char *strchr(const char *s, int c)__attribute__((nonnull));
char *strtok_r(char *str, const char *delim, char **)__attribute__((nonnull(2,3)));
int isdigit(int c);
const char *strerror(int ec);

uint16_t htons(uint16_t word);
uint32_t htonl(uint32_t word);
uint16_t ntohs(uint16_t word);
uint32_t ntohl(uint32_t word);

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
// vim: set ft=c:
