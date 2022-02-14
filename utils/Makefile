SHELL    := /bin/sh

srcdir   := .
objdir   := .

.SUFFIXES:
.SUFFIXES: .c .o

DESTDIR  :=
CC       := gcc

TARGETS  := mkfs.failfs
CPPFLAGS := -I.. -I../src -MMD -MP
CFLAGS   := -O1 -std=c11 -g -Wall -Wextra -pedantic

c_SRC   := $(wildcard *.c)
obj_SRC := $(c_SRC:.c=.o)

all: .d $(TARGETS)

$(TARGETS):	$(TARGETS:=.o)
	$(CC) $(LDFLAGS) -o $@ $<

.d:
	@mkdir -p .d 2>/dev/null

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MF .d/$*.d -c -o $@ $<

clean:
	rm -f $(obj_SRC) $(TARGETS)

.PHONY: clean all

-include $(obj_SRC:%.o=.d/%.d)
