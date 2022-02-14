#ifndef _RAMFS_H
#define _RAMFS_H

#include "klibc.h"
#include "file.h"
#include "proc.h"

extern const struct fs_ops ramfs_ops;

struct ramfs_ino;

struct ramfs_super {
	long maxino;
	const struct ramfs_ino *root;
};

struct ramfs_ino {
	ino_t ino;
	ino_t parenti;
	ino_t nexti;
	ino_t childi;
	const char *const name;
	mode_t special;
	mode_t perms;
	uint64_t flags;
	size_t len;
	const unsigned char *const data;
};
#endif

// vim: set ft=c:
