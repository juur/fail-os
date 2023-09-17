FailOS
======

FailOS is an x86_64 operating system I made. It is incomplete and buggy.
It supports some stuff like ring0/3, multi-tasking, per-process address space
bits of IDE, ethernet, IP, TCP, serial, VGA, simple ELF64 binaries.

It has a basic file system (Linux tool to format in utils/) but it's not very
well tested.

native.bin contains various binaries encoded to form a basic ramfs.
the embedded shell (from fail-shell) does not support PATH searching, so you
will need to execute with full path, e.g. /bin/ls -l /bin
