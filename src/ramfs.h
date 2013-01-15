#ifndef _RAMFS_H
#define _RAMFS_H

#include "file.h"
#include "proc.h"

extern struct fs_ops ramfs_ops;

struct ramfs_ino;

struct ramfs_super {
	uint64 maxino;
	struct ramfs_ino *root;
};

struct ramfs_ino {
	uint64 ino;
	uint64 parenti;
	uint64 nexti;
	uint64 childi;
	char name[64];
	uint64 special;
	uint64 perms;
	uint64 flags;
	uint64 len;
	uint8 *data;
};


uint64 ramfs_read(struct fileh *f, unsigned char *dst, uint64 len);
uint64 ramfs_write(struct fileh *f, const unsigned char *src, uint64 len);
uint64 ramfs_open(struct task *t, struct mount *mnt, char *file, struct fileh *fh);
void ramfs_mount(struct mount *mnt);
uint64 ramfs_close(struct task *t, struct fileh *fh);

#endif
