#ifndef _KLIBC_H
#define _KLIBC_H

#include "errno.h"

typedef unsigned char	uint8;
typedef unsigned short	uint16;
typedef unsigned int 	uint32;
typedef unsigned long 	uint64;
typedef	unsigned long	size_t;
typedef	signed char		int8;
typedef	signed short	int16;
typedef	signed int		int32;
typedef signed long		int64;
typedef int pid_t;

#define va_list __builtin_va_list
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void*)0)
#endif

#define BIT_INDEX(a) ((a)/64)
#define BIT_OFFSET(a) (63-((a)%64)) // FIXME: this was 31- but that broken n=1 frame operatons, but now it's not, it's probably broken n>1 frame operations

#ifndef __cplusplus
#define bool _Bool
#define true 1
#define false 0
#endif

#define SECOND_COMP(x)	((~(x))+1)

void print_bits(uint64 val, const char *bits[], uint64 max, uint8 br);
int putsn(char *text, size_t max);
int puts(char *text);
void printf(const char *format, ...);
void *memcpy(void *dest, void *src, size_t count);
void *memset(void *dest, int val, size_t count);
short *memsetw(short *dest, unsigned short val, size_t count);
char *strcpy(char *dest, const char *source);
char *strncpy(char *dest, const char *source, size_t count);
uint64 strlen(const char *str);
uint64 strcmp(const char *a, const char *b);
uint64 strncmp(const char *a, const char *b, size_t len);
bool isprint(uint8);
uint16 htons(uint16 word);
uint32 htonl(uint32 word);
uint16 ntohs(uint16 word);
uint32 ntohl(uint32 word);

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

#endif

