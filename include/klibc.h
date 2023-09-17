#ifndef _KLIBC_H
#define _KLIBC_H

#include <ktypes.h>

#define CRESET "\x1b[0m"
#define BBLK "\x1b[1;30m"
#define BRED "\x1b[1;31m"
#define BGRN "\x1b[1;32m"
#define BYEL "\x1b[1;33m"
#define BBLU "\x1b[1;34m"
#define BMAG "\x1b[1;35m"
#define BCYN "\x1b[1;36m"
#define BWHT "\x1b[1;37m"

#include <mem.h>

extern int         putsn(const char *text, size_t max) __attribute__((nonnull, access(read_only, 1, 2),tainted_args));
extern int         puts(const char *text) __attribute__((nonnull, access(read_only, 1),tainted_args));
extern int         printf(const char *format, ...) __attribute__((__format__ (__printf__, 1, 2),nonnull(1),access(read_only, 1),tainted_args));
extern void       *_memcpy(void *dest, const void *src, size_t count, const char *, const char *, int) __attribute__((nonnull, access(read_only, 2, 3), returns_nonnull,tainted_args));
#define memcpy(d,s,c) _memcpy((d),(s),(c),__FILE__,__func__,__LINE__)
extern void       *memset(void *dest, int val, size_t count) __attribute__((nonnull, access(read_write, 1, 3),tainted_args));
extern char       *strcpy(char *dest, const char *source) __attribute__((nonnull, access(write_only, 1), access(read_only, 2), returns_nonnull,tainted_args));
extern char       *strncpy(char *dest, const char *source, size_t count) __attribute__((nonnull, access(write_only, 1), access(read_only, 2, 3), returns_nonnull,tainted_args));
extern size_t      strlen(const char *str) __attribute__((nonnull, access(read_only, 1), warn_unused_result,tainted_args));
extern size_t      strnlen(const char *str, size_t) __attribute__((nonnull, access(read_only, 1, 2), warn_unused_result,tainted_args));
extern int         popcountll(unsigned long long x);
extern int         strcmp(const char *a, const char *b) __attribute__((nonnull,tainted_args));
extern char       *strdup(const char *s) __attribute__((nonnull, malloc(_kfree, 1), warn_unused_result,tainted_args));
extern int         strncmp(const char *a, const char *b, size_t len) __attribute__((nonnull, access(read_only, 1, 3), access(read_only, 2, 3),tainted_args));
extern char       *dirname(const char *path) __attribute__((nonnull, malloc(_kfree, 1), access(read_only, 1),tainted_args));
extern char       *basename(const char *path) __attribute__((nonnull, malloc(_kfree, 1), access(read_only, 1),tainted_args));
extern char       *strchr(const char *s, int c) __attribute__((nonnull, access(read_only, 1), warn_unused_result,tainted_args));
extern char       *strtok_r(char *str, const char *delim, char **) __attribute__((nonnull(2,3), access(read_only, 2), warn_unused_result,tainted_args));
extern int         isprint(int) __attribute__((pure, warn_unused_result));
extern int         isdigit(int c) __attribute__((pure, warn_unused_result));
extern const char *strerror(int ec) __attribute__((pure, returns_nonnull, warn_unused_result));
extern uint16_t    htons(uint16_t word) __attribute__((warn_unused_result));
extern uint32_t    htonl(uint32_t word) __attribute__((warn_unused_result));
extern uint16_t    ntohs(uint16_t word) __attribute__((warn_unused_result));
extern uint32_t    ntohl(uint32_t word) __attribute__((warn_unused_result));

extern void        print_bits(uint64_t val, const char *bits[], uint64_t max, uint8_t br) __attribute__((nonnull));


#endif
// vim: set ft=c:
