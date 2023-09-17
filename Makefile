SHELL	:= /bin/bash

srcdir	:= .
objdir	:= .

.SUFFIXES:
.SUFFIXES: .c .s .o

DESTDIR	:=
CC		:= gcc
LD		:= ld
NASM	:= nasm
CPP     := cpp

# Unsure if there is a cleaner way to do this
SYSINCLUDE  := $(shell $(CPP) -v /dev/null -o /dev/null 2>&1 | grep '^ .*gcc/.*include$$' | tr -d ' ')
CPPFLAGS	:= -isystem $(srcdir)/include -I.
CPPFLAGS	+= -isystem "$(SYSINCLUDE)"
CPPFLAGS	+= -MD -MP

APP_CPPFLAGS	:= \
	-isystem ../fail-libc/include \
	-nostdinc \
	-nostdlib \
	-ggdb3 \
	-O0 \
	-fno-builtin
CFLAGS := \
	-ggdb3 \
	-std=c99 \
	-Wpedantic \
	-Wall \
	-Wextra \
	-Wwrite-strings \
	-Wno-packed-bitfield-compat \
	-Wformat=2 \
	-Wformat-overflow=2 \
	-Wno-sign-compare \
	-Wno-misleading-indentation \
	-Wno-unused-parameter \
	-Wmissing-field-initializers \
	-fno-asynchronous-unwind-tables \
	-fdiagnostics-color=always \
	-fdiagnostics-color \
	-fno-pic \
	-mcmodel=large \
	-mno-red-zone \
	-O0
# Uncomment this for gcc analyzer
# CFLAGS += -fanalyzer -fanalyzer-verbosity=2 -fanalyzer-transitivity -fanalyzer-checker=taint 
CFLAGS += -nostdlib -nostdinc -ffreestanding
CFLAGS += 

	#-Wno-unused-but-set-variable \
	#-mno-sse3 \
	# -mno-sse2 \
	#-mno-sse \
	#-mno-mmx \
	#-mfpmath=387 \

LDFLAGS		:= --build-id=none -nostdlib --check-sections -N -g
APP_LDFLAGS	:= --build-id=none -nostdlib --check-sections -N -g
NASMFLAGS	:= -f elf64 -g -w+all

HOST_CPPFLAGS :=
HOST_CPPFLAGS += -MMD -MP -iquote $(srcdir)/include
HOST_CFLAGS   := -std=c99 -pedantic -Wall -Wextra
HOST_LDFLAGS  := 

# Add to this to enable other features, as below
WITH_RAMDISK := 1
WITH_RAMFS := 1
WITH_SERIAL := 1
WITH_PCI := 1
WITH_FAILFS := 1
WITH_IDE := 1
WITH_ACPI := 1
WITH_NET := 1

RCOBJS	:= cpu.o frame.o mem.o init.o klibc.o dev.o \
	page.o proc.o syscall.o file.o block.o
ifdef WITH_NET
RCOBJS += net.o unix.o
CFLAGS += -DWANT_NET
ifdef WITH_IP
RCOBJS += ip.o
CFLAGS += -DWANT_IP
ifneq ($(and $(WITH_ARP),$(WITH_ETH)),)
RCOBJS += arp.o
CFLAGS += -DWANT_ARP
endif
endif
ifdef WITH_ETH
RCOBJS += eth.o
CFLAGS += -DWANT_ETH
endif
endif
ifdef WITH_RAMDISK
RCOBJS += ram.o
CFLAGS += -DWANT_RAMDISK
endif
ifdef WITH_VGA
CFLAGS += -DWANT_VGA
endif
ifdef WITH_SERIAL
CFLAGS += -DWANT_SERIAL
endif
ifdef WITH_ACPI
RCOBJS += acpi.o
CFLAGS += -DWANT_ACPI
endif
ifdef WITH_PCI
RCOBJS += pci.o
CFLAGS += -DWANT_PCI
ifdef WITH_IDE
RCOBJS += ide.o
CFLAGS += -DWANT_IDE
endif
ifdef WITH_PCNET
RCOBJS += pcnet.o
CFLAGS += -DWANT_PCNET
endif
ifdef WITH_AHCI
RCOBJS += ahci.o
CFLAGS += -DWANT_AHCI
endif
endif
ifdef WITH_RAMFS
RCOBJS += ramfs.o
CFLAGS += -DWANT_RAMFS
endif
ifdef WITH_FAILFS
RCOBJS += failfs.o
CFLAGS += -DWANT_FAILFS
endif
ifdef WITH_KEYBOARD
CFLAGS += -DWANT_KEYBOARD
endif
CSRCS	:= $(RCOBJS:.o=.c)
COBJS	:= $(addprefix $(objdir)/obj/,$(RCOBJS))
CSRCS   := $(addprefix $(srcdir)/src/,$(CSRCS))
ASMOBJS	:= mboot.o mboot_hdr.o intr.o
ASMOBJS := $(addprefix $(objdir)/obj/,$(ASMOBJS))
KERNEL	:= $(objdir)/kernel

HOST_COBJS := mkfs.failfs.o
HOST_CSRCS := $(HOST_COBJS:.o=.c)
HOST_UTILS := $(HOST_COBJS:.o=)
HOST_COBJS := $(addprefix $(objdir)/obj/,$(HOST_COBJS))
HOST_CSRCS := $(addprefix $(srcdir)/src/,$(HOST_CSRCS))
HOST_UTILS := $(addprefix $(objdir)/bin/,$(HOST_UTILS))

.PHONY: all clean

all:	.d tags $(KERNEL) $(KERNEL).small $(HOST_UTILS)

dump:
	@echo "COBJS=$(COBJS)"
	@echo "CSRCS=$(CSRCS)"
	@echo "RAW_CSRCS=$(RAW_CSRCS)"
	@echo "DEPS=$(addprefix $(objdir)/.d/,$(notdir $(COBJS:%.o=%.d)))"

.d:
	@mkdir -p .d 2>/dev/null

tags:	$(CSRCS)
	@ctags -R .

# this requires 'fail-shell' to be installed nearby which is hacky
$(objdir)/native.bin/%.o: ../fail-shell/obj/%.o
	cp ../fail-shell/obj/$(@F) $@

$(objdir)/native.bin/%:	$(objdir)/native.bin/%.o
	$(LD) $(APP_LDFLAGS) -T$(srcdir)/src/fail-sh.ld $< ../fail-libc/lib/crt1.o ../fail-libc/lib/libc.a -o $@
	@strip --strip-unneeded $@
	@strip -R .comment $@
	@strip -R .note.gnu.build-id $@
	@strip -R .eh_frame_hdr $@


$(objdir)/native.bin/%.h: $(objdir)/native.bin/%
	xxd -i $< > $@
	sed -i 's,^unsigned,const unsigned,g' $@

mostlyclean:
	rm -f $(HOST_COBJS) \
		$(HOST_UTILS) \
		$(COBJS) \
		$(ASMOBJS) \
		$(KERNEL) $(KERNEL).small

clean: mostlyclean

distclean: clean
	rm -r .d

maintainer-clean: distclean

$(objdir)/obj/%.o:	$(srcdir)/src/%.S
	$(NASM) $(NASMFLAGS) -o $@ $<

$(objdir)/bin/%: $(objdir)/obj/%.o
	$(CC) $(HOST_LDFLAGS) -o $@ $<

$(objdir)/obj/%.o:	$(srcdir)/utils/%.c
	$(CC) $(HOST_CFLAGS) $(HOST_CPPFLAGS) -MF .d/$*.d -c -o $@ $<

$(objdir)/obj/%.o:	$(srcdir)/src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MF .d/$*.d -D_KERNEL -c -o $@ $<

# TODO check this still works with bochs
$(objdir)/bochs.sym $(KERNEL):	$(COBJS) $(ASMOBJS) $(INTOBJS) $(srcdir)/src/script.ld
	$(LD) $(LDFLAGS) -T$(srcdir)/src/script.ld -o $(KERNEL) $(ASMOBJS) $(COBJS) $(INTOBJS)
	@objdump -t $(KERNEL)    | grep "^00000000001" | cut -b 1-16,25- | tr -s ' ' | tr '\t' ' ' | cut -d ' ' -f 1,4 > $(objdir)/bochs.sym

$(KERNEL).small: $(KERNEL)
	@cp $(KERNEL) $(KERNEL).small
	@strip --strip-unneeded $(KERNEL).small
	@strip -R .comment $(KERNEL).small
	@strip -R .note.gnu.build-id $(KERNEL).small
	@strip -R .eh_frame_hdr $(KERNEL).small

-include $(addprefix $(objdir)/.d/,$(notdir $(COBJS:%.o=%.d)))
