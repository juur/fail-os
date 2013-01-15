#ifndef _FILE_H
#define _FILE_H

#include "klibc.h"
#include "proc.h"

struct fileh;
struct mount;

/* fs_ops defines each occurance of a filesystem */

struct fs_ops {
	char name[64];
	uint64 (*read)(struct fileh *, unsigned char *, uint64);
	uint64 (*write)(struct fileh *, const unsigned char *, uint64);
	uint64 (*open)(struct task *, struct mount *, char *, struct fileh *);
	void (*mount)(struct mount *);
	uint64 (*close)(struct task *, struct fileh *);
};

/* mount defines a specific mounted filesystem */

struct mount {
	struct mount *next;
	struct block_dev *dev;
	struct fs_ops *ops;
	void *super;
};

extern struct mount *mounts;

#define FS_DIR  	0x01
#define FS_FILE 	0x02
#define FS_BLOCK    0x04
#define FS_CHAR 	0x08
#define FS_KERNEL	0x10
#define	FS_SOCKET	0x20
#define FS_BOUND	0x40
#define FS_LISTEN	0x80

/* fileh is a file handle, it defines a file (inode) on a specific
 * filesystem (mount) */

struct fileh {
	uint64	inode;		// inode on fs, 0 for sockets
	uint64	special;	// major|minor, 0 for sockets
	struct mount *fs;	// ptr to fs structure, NULL for sockets
	uint64	perms;		// file perms/flags
	uint64	seek;		// offset in bytes, 0 for sockets
	uint64	flags;
	union {				// where the file is special
		struct block_dev *blk_dev;
		struct char_dev *char_dev;
		struct net_dev *net_dev;
		void *dev;
	} sdev;
	struct task *task;	// NULL for kernel
	uint64	family,type,protocol;		// sys_socket params saved for forking a new socket
	struct fileh *listen_next;
	void *priv;
};

struct mount *do_mount(struct block_dev *dev, char *p, struct fs_ops *fsops);
uint64 do_write(struct fileh *fh, unsigned char *src, uint64 len);
struct fileh *do_open(const char *name, struct task *t, int flags);
uint64 do_read(struct fileh *fh, unsigned char *dst, uint64 len);
void do_seek(struct fileh *fh, uint64 off);
void do_close(struct fileh *fh, struct task *t);
struct fileh *do_dup(struct fileh *fh, struct task *t);

#endif
