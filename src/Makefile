CC=@gcc
LD=@ld
NASM=@nasm
CFLAGS=-m64 -ffreestanding -nostdlib -nodefaultlibs -nostdinc -fno-stack-protector -std=c99 -g -Wall -Wno-packed-bitfield-compat
LDFLAGS=--build-id=none -nostdlib --check-sections -N -g
NASMFLAGS=-f elf64 -g

COBJS=tcp.o arp.o acpi.o pcnet.o ahci.o ide.o eth.o ip.o slip.o net.o ppp.o cpu.o frame.o mem.o init.o klibc.o dev.o page.o proc.o syscall.o pci.o block.o ram.o file.o ramfs.o end.o
ASMOBJS=mboot.o mboot_hdr.o intr.o
KERNEL=kernel

all:	default

default:	$(KERNEL) task2 tags
#	mount mnt
#	cp kernel mnt/kernel.bin
##	strip mnt/kernel.bin
#	sleep 0.1s
#	umount mnt
#	sync

tags:	$(COBJS)
	@echo "[CTAGS]"
	@ctags -R .

task2: crt0.c task2.c syscalls.o libc.c task2.ld
	@echo "[LINK] $@"
	$(CC) task2.c -o task2.o $(CFLAGS) -c
	$(CC) crt0.c -o crt0.o $(CFLAGS) -c
	$(CC) libc.c -o libc.o $(CFLAGS) -c
	$(LD) $(LDFLAGS) -Ttask2.ld -o task2 crt0.o task2.o libc.o syscalls.o
	@cp task2 task2.big
	@strip --strip-unneeded task2
	@strip -R .comment task2
	@strip -R .note.gnu.build-id task2
	@strip -R .eh_frame_hdr task2
#@strip -R .eh_frame task2

task2.h: task2
	@xxd  -i task2 > task2.h

busybox.h: busybox
	@xxd  -i busybox > busybox.h

task3.h: 
	@xxd -i task3 > task3.h

clean:
	@echo "[CLEAN]"
	@rm -f *.o kernel .depend bochs.sym syms.h
	@echo "[DEPEND]"
	$(CC) -MM *.c >.depend
	
%.o:	%.S
	@echo "[NASM] $@"
	$(NASM) $(NASMFLAGS) -o $@ $<

%.o:	%.c
	@echo "[CC] $@"
	$(CC) $(CFLAGS) -D_KERNEL -c -o $@ $<

kernel:		$(COBJS) $(ASMOBJS) script.ld
	@echo "[LINK] $@"
	$(CC) $(CFLAGS) -D_KERNEL -c -o dummy-syms.o dummy-syms.c
	$(LD) $(LDFLAGS) -Tscript.ld -o $(KERNEL) $(ASMOBJS) $(COBJS) dummy-syms.o
	@objdump -t kernel  | grep "^00000000001" | cut -b 1-16,25- | tr -s ' ' | tr '\t' ' ' | cut -d ' ' -f 1,4 > bochs.sym
	@./mksyms
	$(CC) $(CFLAGS) -D_KERNEL -c -o syms.o syms.c
	$(LD) $(LDFLAGS) -Tscript.ld -o $(KERNEL) $(ASMOBJS) $(COBJS) syms.o
	@mcopy -o -i ../arse.img $(KERNEL) ::
	@echo "Put CVS back"
#	@cvs commit -m ""

.depend: *.c
	@echo "[DEPEND]"
	$(CC) -MM *.c >.depend

include .depend
