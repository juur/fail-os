#ifndef _INTR_H
#define _INTR_H

#include "klibc.h"

extern __attribute__((interrupt))  void _isr0(void*);
extern __attribute__((interrupt))  void _isr1(void*);
extern __attribute__((interrupt))  void _isr2(void*);
extern __attribute__((interrupt))  void _isr3(void*);
extern __attribute__((interrupt))  void _isr4(void*);
extern __attribute__((interrupt))  void _isr5(void*);
extern __attribute__((interrupt))  void _isr6(void*);
extern __attribute__((interrupt))  void _isr7(void*);
extern __attribute__((interrupt))  void _isr8(void*,uint64_t);
extern __attribute__((interrupt))  void _isr9(void*);
extern __attribute__((interrupt))  void _isr10(void*,uint64_t);
extern __attribute__((interrupt))  void _isr11(void*,uint64_t);
extern __attribute__((interrupt))  void _isr12(void*,uint64_t);
extern __attribute__((interrupt))  void _isr13(void*,uint64_t);
extern __attribute__((interrupt))  void _isr14(void*,uint64_t);
extern __attribute__((interrupt))  void _isr15(void*);
extern __attribute__((interrupt))  void _isr16(void*);
extern __attribute__((interrupt))  void _isr17(void*,uint64_t);
extern __attribute__((interrupt))  void _isr18(void*);
extern __attribute__((interrupt))  void _isr19(void*);
extern __attribute__((interrupt))  void _isr20(void*);
extern __attribute__((interrupt))  void _isr21(void*,uint64_t);
extern __attribute__((interrupt))  void _isr22(void*);
extern __attribute__((interrupt))  void _isr23(void*);
extern __attribute__((interrupt))  void _isr24(void*);
extern __attribute__((interrupt))  void _isr25(void*);
extern __attribute__((interrupt))  void _isr26(void*);
extern __attribute__((interrupt))  void _isr27(void*);
extern __attribute__((interrupt))  void _isr28(void*);
extern __attribute__((interrupt))  void _isr29(void*);
extern __attribute__((interrupt))  void _isr30(void*,uint64_t);
extern __attribute__((interrupt))  void _isr31(void*);
extern __attribute__((interrupt))  void _isr32(void*);
extern __attribute__((interrupt))  void _isr33(void*);
extern __attribute__((interrupt))  void _isr34(void*);
extern __attribute__((interrupt))  void _isr35(void*);
extern __attribute__((interrupt))  void _isr36(void*);
extern __attribute__((interrupt))  void _isr37(void*);
extern __attribute__((interrupt))  void _isr38(void*);
extern __attribute__((interrupt))  void _isr39(void*);
extern __attribute__((interrupt))  void _isr40(void*);
extern __attribute__((interrupt))  void _isr41(void*);
extern __attribute__((interrupt))  void _isr42(void*);
extern __attribute__((interrupt))  void _isr43(void*);
extern __attribute__((interrupt))  void _isr44(void*);
extern __attribute__((interrupt))  void _isr45(void*);
extern __attribute__((interrupt))  void _isr46(void*);
extern __attribute__((interrupt))  void _isr47(void*);

extern void def_isr(void);

#endif

// vim: set ft=c:
