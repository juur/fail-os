SHELL	:= /bin/sh

srcdir	:= .
objdir	:= .

DESTDIR	:=
CC		:= gcc
LD		:= ld
NASM	:= nasm
CPPFLAGS	:= -I.
CPPFLAGS	+= -MMD -MP
APP_CPPFLAGS	:= -I../../fail-libc/include
CFLAGS		:= -ggdb3 -ffreestanding -nostdlib -nostdinc -std=c11 \
	-pedantic -Wall -Wextra \
	-Wno-packed-bitfield-compat \
	-Wno-unused-parameter \
	-Wformat=2 \
	-fno-asynchronous-unwind-tables \
	-Wno-sign-compare \
	-Wno-misleading-indentation \
	-mno-red-zone \
	-O0

	#-Wno-unused-but-set-variable \
	#-mno-sse3 \
	# -mno-sse2 \
	#-mno-sse \
	#-mno-mmx \
	#-mfpmath=387 \

LDFLAGS		:= --build-id=none -nostdlib --check-sections -N -g
NASMFLAGS	:= -f elf64 -g -w+all

#COBJS=cpu.o acpi.o frame.o mem.o init.o klibc.o dev.o page.o proc.o syscall.o ram.o file.o ramfs.o block.o pci.o end.o
COBJS	:=acpi.o tcp.o cpu.o frame.o mem.o init.o ip.o net.o klibc.o dev.o \
	page.o proc.o syscall.o pci.o file.o ramfs.o ide.o block.o ahci.o \
	failfs.o pcnet.o arp.o eth.o ram.o
#INTOBJS	:=int_0x20.o
#syms.o
#COBJS	+=arp.o ppp.o slip.o eth.o pcnet.o ahci.o ide.o
COBJS	+=end.o
CSRCS	:=$(COBJS:.o=.c)
ASMOBJS	:=mboot.o mboot_hdr.o intr.o
KERNEL	:=kernel

.PHONY: all clean

all:	.d task2.h tags $(KERNEL) $(KERNEL).small

.d:
	@mkdir -p .d 2>/dev/null

tags:	$(CSRCS)
	@ctags -R .

task2: task2.c task2.ld syscall.h
	$(CC) -no-pie task2.c -o task2.o $(CFLAGS) $(APP_CPPFLAGS) -c
	$(LD) $(LDFLAGS) -Ttask2.ld -o task2 ../../fail-libc/lib/crt1.o task2.o ../../fail-libc/lib/libc.a
	@cp task2 task2.big
	@strip --strip-unneeded task2
	@strip -R .comment task2
	@strip -R .note.gnu.build-id task2
	@strip -R .eh_frame_hdr task2

#task3: task3.c task3.ld syscall.h
#	$(CC) -no-pie task3.c -o task3.o $(CFLAGS) -c
#	$(LD) $(LDFLAGS) -no-pie -Ttask3.ld -o task3 task3.o
#	@cp task3 task3.big
#	@strip --strip-unneeded task3
#	@strip -R .comment task3
#	@strip -R .note.gnu.build-id task3
#	@strip -R .eh_frame_hdr task3


#@strip -R .eh_frame task2

task2.h: task2
	xxd -i $< > $@
	sed -i 's,^unsigned,const unsigned,g' $@

#busybox.h: busybox
#	xxd  -i busybox > busybox.h

#task3.h: task3
#	xxd -i $< > $@
#	sed -i 's,^unsigned,const unsigned,g' $@

mostlyclean:
	rm -f $(COBJS) $(ASMOBJS) kernel kernel.small task2 task2.big task2.o task2.h syms.c task3 task3.o task3.big task3.h

clean: mostlyclean

distclean: clean
	rm -r .d

maintainer-clean: distclean

%.o:	%.S
	$(NASM) $(NASMFLAGS) -o $@ $<

#int_0x20.o:	int_0x20.c
#	$(CC) $(CFLAGS) -mgeneral-regs-only -mno-red-zone $(CPPFLAGS) -MF .d/$*.d -D_KERNEL -c -o $@ $<

%.o:	%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MF .d/$*.d -D_KERNEL -c -o $@ $<

.NOTPARALLEL: kernel.small kernel

bochs.sym kernel.small kernel:	task2.h $(COBJS) $(ASMOBJS) $(INTOBJS) script.ld
	$(LD) $(LDFLAGS) -Tscript.ld -o $(KERNEL) $(ASMOBJS) $(COBJS) $(INTOBJS)
	@objdump -t kernel    | grep "^00000000001" | cut -b 1-16,25- | tr -s ' ' | tr '\t' ' ' | cut -d ' ' -f 1,4 > bochs.sym
	@objdump -t task2.big | grep "^000000004"   | cut -b 1-16,25- | tr -s ' ' | tr '\t' ' ' | cut -d ' ' -f 1,4 >>bochs.sym
#$(LD) $(LDFLAGS) -Tscript.ld -o $(KERNEL) $(ASMOBJS) $(COBJS)
	@cp $(KERNEL) $(KERNEL).small
	@strip --strip-unneeded $(KERNEL).small
	@strip -R .comment $(KERNEL).small
	@strip -R .note.gnu.build-id $(KERNEL).small
	@strip -R .eh_frame_hdr $(KERNEL).small
	mcopy -o -i ../boot.img $(KERNEL).small ::kernel

#	$(CC) $(CFLAGS) -D_KERNEL -c -o dummy-syms.o dummy-syms.c
# dummy-syms.o
#	@./mksyms
#	$(CC) $(CFLAGS) -D_KERNEL -c -o syms.o syms.c
# syms.o
#

-include $(COBJS:%.o=.d/%.d)
