#include "klibc.h"
#include "ramfs.h"
#include "dev.h"
#include "cpu.h"
#include "mem.h"
#include "proc.h"
#include "task2.h"

struct fs_ops ramfs_ops = {
	"ramfs",
	ramfs_read,
	ramfs_write,
	ramfs_open,
	ramfs_mount,
	ramfs_close
};

#define TTY	DEV_ID(CON_MAJOR,CON_MINOR)
#define HD0	DEV_ID(IDE_MAJOR,0)

struct ramfs_ino t_ramfs_ino[] = {
 {0,-1,-1, 1,"",		0,		755, FS_DIR,			0,	NULL },
 {1, 0, 3, 2,"dev",		0,		755, FS_DIR,		 	0,	NULL },
 {2, 1,-1,-1,"dev/tty",	TTY,	644, FS_FILE|FS_CHAR,	0,	NULL },
 {3, 0,-1,-1,"init",	0,		755, FS_FILE,			sizeof(task2),	task2 },
 {4, 1,-1,-1,"dev/hd0", HD0,	644, FS_FILE|FS_BLOCK,	0,	NULL },
 //{3, 0,-1,-1,"init",	0,		755, FS_FILE,			1045992,	busybox },
 //{3, 0,-1,-1,"init",	0,		755, FS_FILE,			1045992,	task3 },
 
 {-1,-1,-1,-1,"\0",0,0,0,0,NULL}
};

struct ramfs_super t_ramfs_super = {
	2, &t_ramfs_ino[0]
};

uint64 ramfs_read(struct fileh *f, unsigned char *dst, uint64 len)
{
	struct ramfs_super *super = (struct ramfs_super *)f->fs->super;
	struct ramfs_ino *ino = &super->root[f->inode];
	//int i;
	unsigned char *src = (ino->data + f->seek);
	
	if(ino->flags & FS_DIR) {
		return 0;
	} else if((ino->flags & (FS_FILE|FS_CHAR)) == (FS_FILE|FS_CHAR)) {
		printf("file char\n");
	} else if((ino->flags & (FS_FILE|FS_BLOCK)) == (FS_FILE|FS_BLOCK)) {
		printf("file block\n");
	} else if((ino->flags & FS_FILE) == FS_FILE) {
		if(f->flags & FS_KERNEL) {
			/* FIXME */
			//printf("ramfs_read: %x -> %x len=%x\n", src, dst, len);
			memcpy(dst, src, len);
			//printf("ramfs_read: done\n");
		} else {
			copy_to_user(dst, f->task, ino->data, len);
		}
	}
	return len;
}

uint64 ramfs_write(struct fileh *f, const unsigned char *src, uint64 len)
{
	struct ramfs_super *super = (struct ramfs_super *)f->fs->super;
	struct ramfs_ino *ino = &super->root[f->inode];

	//printf("ramfs_write: %x len %x\n", src, len);

	if(ino->flags & FS_DIR) {
		return 0;
	} else if((ino->flags & (FS_FILE|FS_CHAR)) == (FS_FILE|FS_CHAR)) {
	} else if((ino->flags & (FS_FILE|FS_BLOCK)) == (FS_FILE|FS_BLOCK)) {
	} else if((ino->flags & FS_FILE) == FS_FILE) {
	}
	return 0;
}

uint64 ramfs_close(struct task *t, struct fileh *fh)
{
	return 0;
}

uint64 ramfs_open(struct task *t, struct mount *mnt, char *file, 
		struct fileh *fh)
{
	//struct ramfs_super *super = (struct ramfs_super *)mnt->super;
	struct ramfs_ino *ret = NULL;
	int i = 0;
	bool found = false;

	do {
		if (t_ramfs_ino[i].ino == -1) {
			found = true;
		} else if (!(strcmp((char *)&t_ramfs_ino[i].name, file))) {
			ret = &t_ramfs_ino[i];
			found = true;
		} else {
			i++;
		}
	} while (!found);

	if(!ret) return -1;

	fh->special = ret->special;
	fh->flags = ret->flags;

	if(t) {
		fh->task = t;
	} else {
		fh->task = NULL;
		fh->flags |= FS_KERNEL;
	}

	return ret->ino;
}

void ramfs_mount(struct mount *mnt)
{
	mnt->super = &t_ramfs_super;
}
