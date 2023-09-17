#include "klibc.h"
#include "ramfs.h"
#include "dev.h"
#include "cpu.h"
#include "mem.h"
#include "proc.h"
#include "task2.h"
#include "fail-jvm-failos.h"
#include "busybox.h"
#include "fail-sh.h"
#include "ls.h"
#include "fail-init.h"
#include "cat.h"
#include "dd.h"
#include "date.h"
#include "head.h"
#include "tail.h"
#include "echo.h"
#include "sed.h"
#include "cp.h"
#include "busybox-x86_64.h"

#define TTY	DEV_ID(SER_MAJOR,SER_0_MINOR)
#define HD0	DEV_ID(IDE_MAJOR,0)
#define NUL DEV_ID(TTY_MAJOR,NUL_MINOR)
#define CON DEV_ID(CON_MAJOR,CON_MINOR)

static const char inittab[] =
"# Level to run in\n"
"id:s:initdefault:\n"
"si::sysinit:\n"
"~:s:wait:/bin/sh\n"
"\n"
"l0:0:wait:/etc/init.d/rc 0\n"
"l1:1:wait:/etc/init.d/rc 1\n"
"l2:2:wait:/etc/init.d/rc 2\n"
"l3:3:wait:/etc/init.d/rc 3\n"
"l4:4:wait:/etc/init.d/rc 4\n"
"l5:5:wait:/etc/init.d/rc 5\n"
"l6:6:wait:/etc/init.d/rc 6\n"
"\n"
"ca::ctrlaltdel:/sbin/shutdown -t1 -h now\n"
"\n"
"1:23:respawn:/sbin/getty tty1 VC linux\n"
"2:23:respawn:/sbin/getty tty2 VC linux\n"
"3:23:respawn:/sbin/getty tty3 VC linux\n"
"4:23:respawn:/sbin/getty tty4 VC linux\n"
"S0:3:respawn:/sbin/getty -L 9600 ttyS0 vt320\n"
"S1:3:respawn:/sbin/mgetty -x0 -D ttyS1\n";

/*
 ino par nex chi name    spec    perm  flags */
struct ramfs_ino t_ramfs_ino[] = {

 {1,  1, -1,  2, "/"   ,    0  , 0755, FS_DIR          , 0                            , NULL  }, 
 {2,  1,  4,  3, "dev" ,    0  , 0755, FS_DIR          , 0                            , NULL  }, 
 {3,  2,  5, -1, "tty" ,    TTY, 0644, FS_FILE|FS_CHAR , 0                            , NULL  }, 
 {4,  1,  6, -1, "init",    0  , 0755, FS_FILE         , sizeof(native_bin_fail_init) , (const char *)native_bin_fail_init }, 
 {5,  2, 10, -1, "hd0" ,    HD0, 0644, FS_FILE|FS_BLOCK, 0                            , NULL  }, 
 {6,  1,  7, -1, "java",    0  , 0755, FS_FILE         , sizeof(fail_jvm_failos)      , (const char *)fail_jvm_failos },
 {7,  1,  8, -1, "mnt" ,    0  , 0755, FS_DIR          , 0                            , NULL  },
 {8,  1, 12,  9, "bin" ,    0  , 0755, FS_DIR          , 0                            , NULL  },
 {9,  8, 17, -1, "sh"  ,    0  , 0755, FS_FILE         , sizeof(native_bin_fail_sh)   , (const char *)native_bin_fail_sh },
 {10, 2, 11, -1, "null",    NUL, 0666, FS_FILE|FS_CHAR , 0                            , NULL  },
 {11, 2, -1, -1, "console", CON, 0600, FS_FILE|FS_CHAR , 0                            , NULL  },
 {12, 1, 13, -1, "sys" ,    0  , 0755, FS_DIR          , 0                            , NULL  },
 {13, 1, 14, -1, "proc",    0  , 0755, FS_DIR          , 0                            , NULL  },
 {14, 1, 16, 15, "etc",     0  , 0755, FS_DIR          , 0                            , NULL  },
 {15,14, -1, -1, "inittab", 0  , 0644, FS_FILE         , sizeof(inittab)              , (const char *)inittab },
 {16, 1, -1, -1, "run",     0  , 0777, FS_DIR          , 0                            , NULL  },
 {17, 8, 18, -1, "ls",      0  , 0777, FS_FILE         , sizeof(native_bin_ls)        , (const char *)native_bin_ls },
 {18, 8, 19, -1, "cat",     0  , 0777, FS_FILE         , sizeof(native_bin_cat)       , (const char *)native_bin_cat },
 {19, 8, 20, -1, "dd",      0  , 0777, FS_FILE         , sizeof(native_bin_dd)        , (const char *)native_bin_dd },
 {20, 8, 21, -1, "date",    0  , 0777, FS_FILE         , sizeof(native_bin_date)      , (const char *)native_bin_date },
 {21, 8, 22, -1, "head",    0  , 0777, FS_FILE         , sizeof(native_bin_head)      , (const char *)native_bin_head },
 {22, 8, 23, -1, "tail",    0  , 0777, FS_FILE         , sizeof(native_bin_tail)      , (const char *)native_bin_tail },
 {23, 8, 24, -1, "echo",    0  , 0777, FS_FILE         , sizeof(native_bin_echo)      , (const char *)native_bin_echo },
 {24, 8, 25, -1, "sed",     0  , 0777, FS_FILE         , sizeof(native_bin_sed)       , (const char *)native_bin_sed },
 {25, 8, 26, -1, "cp",      0  , 0777, FS_FILE         , sizeof(native_bin_cp)        , (const char *)native_bin_cp },
 {26, 8, -1, -1, "busybox", 0  , 0777, FS_FILE         , sizeof(native_bin_busybox_x86_64),(const char *)native_bin_busybox_x86_64 },

 {27, 0, 0, 0,NULL,0,0,0,0,NULL},
 {28, 0, 0, 0,NULL,0,0,0,0,NULL},
 {29, 0, 0, 0,NULL,0,0,0,0,NULL},
 {30, 0, 0, 0,NULL,0,0,0,0,NULL},
 {-1,-1,-1,-1,"\0",0,0,0,0,NULL}
};

#define MAX_INO_RO 26

#undef TTY
#undef HD0
#undef NUL
#undef CON

const struct ramfs_super t_ramfs_super = {
	.maxino = sizeof(t_ramfs_ino)/sizeof(const struct ramfs_ino),
	.root   = &t_ramfs_ino[0]
};

__attribute__((nonnull))
ssize_t ramfs_read(struct fileh *const f, char *const dst, const size_t reqlen, const off_t from)
{
	//printf("ramfs_read: reqlen=%lx from=%lx\n", reqlen, from);

	if(reqlen == 0)
		return 0;

	if(!is_valid((const uint8_t *)dst))
		return -EFAULT;

	//printf("ramfs_read: f->inode: %p f->inode->priv: %p\n",
	//		(void *)f->inode,
	//		(void *)f->inode->priv);
	
	const struct ramfs_ino *ino = (const struct ramfs_ino *)f->inode->priv;
	const char *src = ((char *)ino->data) + from;

	if(from < 0 || (size_t)from > ino->len)
		return 0;

	size_t len = reqlen;

	if(len + from > ino->len)
		len = ino->len - from;

	//printf("ramfs_read: seek:%lx len:%lx ino:%p\n", f->seek, len, (void *)ino);
	//printf("ramfs_read: ino.flags:%lx ino.name:%s ino.ino:%lx\n", ino->flags, ino->name, ino->ino);
	
	if(ino->flags & FS_DIR) {
		//printf("ramfs_read: file dir\n");
		return -EBADF;
	} else if((ino->flags & (FS_FILE|FS_CHAR)) == (FS_FILE|FS_CHAR)) {
		//printf("ramfs_read: file char\n");
		return -EBADF;
	} else if((ino->flags & (FS_FILE|FS_BLOCK)) == (FS_FILE|FS_BLOCK)) {
		//printf("ramfs_read: file block\n");
		return -EBADF;
	} else if((ino->flags & FS_FILE) == FS_FILE) {
		if(f->flags & FS_KERNEL) {
			/* FIXME - bounds checking*/
			//printf("ramfs_read: %p -> %p len=%lx\n", (void *)src, (void *)dst, len);
			memcpy(dst, src, len);
			//printf("ramfs_read: done\n");
		} else if (f->task) {
			//printf("ramfs_read: copy_to_user\n");
			memcpy(dst, ino->data, len);
		} else
			return -EBADF;
	} else {
		//printf("ramfs_read: unknown file type\n");
		return -EBADF;
	}
	return len;
}

__attribute__((nonnull))
ssize_t ramfs_write(struct fileh *f, const char *src, size_t len, off_t from)
{
	//printf("ramfs_write: (f=%p,src=%p,len=0x%lx,from=0x%lx) [inode=%p]\n", (void *)f, (void *)src, len, from, (void *)f->inode);

	if (len == 0)
		return 0;

	if (f->inode == NULL) {
		//printf("ramfs_write: inode is NULL\n");
		return -EBADF;
	}

	const struct ramfs_ino *ino = (const struct ramfs_ino *)f->inode->priv;


	if (ino == NULL) {
		//printf("ramfs_write: inode is empty!\n");
		return -EBADF;
	} if (ino->flags & FS_DIR) {
		return -EBADF;
	} else if((ino->flags & (FS_FILE|FS_CHAR)) == (FS_FILE|FS_CHAR)) {
		if(f->sdev.char_dev && f->sdev.char_dev->ops)
			return f->sdev.char_dev->ops->write(f->sdev.char_dev, src, len);
		else {
			printf("ramfs_write: missing sdev/\n");
			hlt();
			return -1;
		}
	} else if((ino->flags & (FS_FILE|FS_BLOCK)) == (FS_FILE|FS_BLOCK)) {
		return block_write(f->sdev.blk_dev, src, len, from);
	} else if((ino->flags & FS_FILE) == FS_FILE) {
		return -EBADF;
	}
	return 0;
}

__attribute__((nonnull(2)))
static long ramfs_close(__attribute__((unused)) struct task *const t, struct fileh *const fh)
{
	fh->inode->priv = NULL;

	return 0;
}

__attribute__((nonnull(2,3,7)))
static ino_t ramfs_create(struct task *t, struct mount *m, struct fileh * f, int fl, mode_t md, dev_t rdev, void **p)
{
	//printf("ramfs_create: called t=%p m=%p f=%p fl=%x md=%x rdev=%x p=%p ",
	//		(void *)t, (void *)m, (void *)f, fl, md, rdev, (void *)p);
	//printf("fsent=%p fsent.name=%s\n", (void *)f->fsent, f->fsent->name);
	//
	
	struct ramfs_ino *new = NULL;
	
	for (ino_t i = MAX_INO_RO; t_ramfs_ino[i].ino != -1UL; i++)
		if (t_ramfs_ino[i].name == NULL) {
			new = &t_ramfs_ino[i];	
			break;
		}

	if ( new == NULL )
		return -ENOSPC;

	new->perms = md;
	new->childi = -1;
	new->parenti = f->fsent->self_ino;
	new->perms   = (0666 & ~t->umask);


	switch (md & S_IFMT)
	{
		case S_IFIFO:
			new->special = FS_FILE|FS_FIFO;
			break;
		default:
			return -EINVAL;
	}

	t_ramfs_ino[new->parenti].childi = 16;
	*p = new;
	printf("ramfs_create: new ino %lu\n", new->ino);
	return new->ino;
}

__attribute__((nonnull(2,3,4))) 
static ino_t ramfs_open(
	_Unused struct task *const t, 
	_Unused struct mount *const mnt, 
	struct fsent *const fsent, 
	_Unused struct fileh *const fh, 
	const int flags, 
	_Unused const mode_t mode,
	void **priv)
{
	//struct ramfs_super *super = (struct ramfs_super *)mnt->super;
	const struct ramfs_ino *ret = NULL;
	int i = 0;
	bool found = false;

	//printf("ramfs_open: t:%p mnt:%p file:%s fh:%p\n", (void *)t, (void *)mnt, fsent->name, (void *)fh);

	do {
		if (t_ramfs_ino[i].ino == -1UL) {
			found = true;
		} else if (!(strcmp(t_ramfs_ino[i].name, fsent->name))) {
			ret = &t_ramfs_ino[i];
			found = true;
		} else {
			i++;
		}
	} while (!found);

	if(!ret) {
		//printf("ramfs_open: no such file: %s\n", fsent->name);
		return -ENOENT;
	}

	//printf("ramfs_open: ops=%s\n", fh->fs->ops->name);

	if ( !(ret->flags & (FS_CHAR|FS_BLOCK)) && (flags & (O_CREAT)) ) {
		//printf("ramfs_open: EACCES: ret->flags=%lx vs flags=%x\n", ret->flags, flags);
		return -EACCES;
	}

	//printf("ramfs_open: setting priv to %p\n", (void*)ret);
	
	fh->flags |= ret->flags & (FS_FILE|FS_DIR|FS_FIFO|FS_CHAR|FS_BLOCK);
	*priv = (void *)ret;

	return ret->ino;
}

__attribute__((nonnull))
static long ramfs_mount(struct mount *mnt)
{
	mnt->super = (void *)&t_ramfs_super;
	return 0;
}

__attribute__((nonnull))
static long ramfs_umount(__attribute__((unused)) struct mount *const mnt)
{
	return 0;
}

__attribute__((nonnull(2)))
static long ramfs_ioctl(
		__attribute__((unused)) struct task *const t, 
		struct fileh *const fh, 
		const uint64_t req, 
		...)
{
	va_list ap;
	va_start(ap, req);
	int rc = -EBADF;
	struct inode *inode = fh->inode;
	if(inode == NULL)
		goto fail;

	switch(req)
	{
		default:
			rc = -EINVAL;
			goto fail;
	}

fail:
	va_end(ap);
	return rc;
}

__attribute__((nonnull))
static long ramfs_sync_inode(struct inode *const inode, const ino_t ino, const int mode)
{
	struct ramfs_ino *rfs_ino;

	//printf("ramfs_sync_inode: %lu\n", ino);

    if(mode != SYNC_READ && ino <= MAX_INO_RO) {
		//printf("ramfs_sync_inode: attempt to SYNC_WRITE for inode=%lu\n", ino);
        return 0;
    }

	if(inode->priv == NULL) {
		for(int i = 0; t_ramfs_ino[i].ino != -1UL; i++)
			if(t_ramfs_ino[i].ino == ino) {
				inode->priv = (void *)&t_ramfs_ino[i];
				break;
			}
	}

	rfs_ino = (struct ramfs_ino *)inode->priv;

	if(rfs_ino == NULL)
		return -EBADF;

	switch (mode) {
		case SYNC_READ:
			inode->st_dev   = inode->mnt->dev->devid;
			inode->st_ino   = rfs_ino->ino;
			inode->st_rdev  = rfs_ino->special;
			inode->st_size  = rfs_ino->len;
			inode->flags    = rfs_ino->flags;
			inode->st_uid   = 0;
			inode->st_gid   = 0;

			if (rfs_ino->flags & FS_DIR) {
				inode->st_mode = S_IFDIR;
			} else if (rfs_ino->flags & FS_CHAR) {
				inode->st_mode = S_IFCHR;
			} else if (rfs_ino->flags & FS_BLOCK) {
				inode->st_mode = S_IFBLK;
			} else if (rfs_ino->flags & FS_FILE) {
				inode->st_mode = S_IFREG;
			}

			inode->st_mode  |= rfs_ino->perms;

			break;

		case SYNC_WRITE:
			break;
	}

	return 0;
}

__attribute__((nonnull)) 
static long ramfs_sync_fsent(struct fsent *fsent, const int mode)
{
	//printf("ramfs_sync_fsent: %ld %s: ", fsent->self_ino, fsent->name);

    if(mode != SYNC_READ && fsent->self_ino <= MAX_INO_RO) {
		//printf("-EACCES\n");
		return 0;
        return -EACCES;
	}

	for (int i = 0; t_ramfs_ino[i].ino != -1UL; i++) {
		if (t_ramfs_ino[i].ino != fsent->self_ino)
			continue;

		switch (mode) {
			case SYNC_READ:
				strcpy((char *)fsent->name, t_ramfs_ino[i].name);
				fsent->sibling_ino = t_ramfs_ino[i].nexti;
				fsent->child_ino   = t_ramfs_ino[i].childi;
				fsent->flags       = t_ramfs_ino[i].flags;
				break;

			case SYNC_WRITE:
				if (t_ramfs_ino[i].name)
					kfree((char *)t_ramfs_ino[i].name);
				t_ramfs_ino[i].name = strdup(fsent->name);
				t_ramfs_ino[i].nexti = fsent->sibling_ino;
				t_ramfs_ino[i].childi = fsent->child_ino;
				t_ramfs_ino[i].flags = fsent->flags;
				break;
		}

		//printf("%s\n", fsent->name);

		/* TODO */

		return 0;
	}

	//printf("-ENOENT\n");
	return -ENOENT;
}

__attribute__((nonnull(2,3,4)))
static ino_t ramfs_mkdir(struct task *tsk, struct mount *m, struct fsent *f, const char *name, mode_t mode)
{
	return -ENOSYS;
}

__attribute__((nonnull(2)))
static long ramfs_link(struct task *t, struct fsent *f, ino_t ino)
{
	//printf("ramfs_link: t=%p f=%p[%s] ino=%lu\n", (void *)t, (void *)f, f->name, ino);

	if (ino > (ino_t)t_ramfs_super.maxino)
		return -ENOSPC;

	if (ino <= MAX_INO_RO)
		return -EACCES;

	if (t_ramfs_ino[ino].name) {
		//printf("ramfs_link: freeing '%s'\n", t_ramfs_ino[ino].name);
		kfree((void *)t_ramfs_ino[ino].name);
	}
	t_ramfs_ino[ino].name = strdup(f->name);
	return 0;
}

__attribute__((nonnull(2,4,5))) 
static long ramfs_find( _Unused struct task *tsk, struct mount *mnt, struct fsent *cwd, const char *file, struct fsent **ret)
{
	long rc = -ENOENT;
	ino_t parent_ino = cwd ? cwd->self_ino : 1;
	*ret = NULL;

	//printf("ramfs_find: %s\n", file);

	for(int i = 0; t_ramfs_ino[i].ino != -1UL; i++)
	{
		if(t_ramfs_ino[i].parenti != parent_ino)
			continue;

		if(strcmp(file, t_ramfs_ino[i].name))
			continue;

		//printf("ramfs_find: match ino=%lu\n", t_ramfs_ino[i].ino);

		if((*ret = create_fsent(mnt, cwd, t_ramfs_ino[i].ino, &rc, file, false)) != NULL)
			return t_ramfs_ino[i].ino; 
	}

	return rc;
}

const struct fs_ops ramfs_ops = {
	"ramfs",

	.close      = ramfs_close,
	.create     = ramfs_create,
	.find       = ramfs_find,
	.ioctl      = ramfs_ioctl,
	.mount      = ramfs_mount,
	.open       = ramfs_open,
	.read       = ramfs_read,
	.sync_inode = ramfs_sync_inode,
	.sync_fsent = ramfs_sync_fsent,
	.umount     = ramfs_umount,
	.write      = ramfs_write,
	.link		= ramfs_link,
	.mkdir		= ramfs_mkdir
};


