#include "klibc.h"
#include "ramfs.h"
#include "dev.h"
#include "cpu.h"
#include "mem.h"
#include "proc.h"
#include "task2.h"

#define TTY	DEV_ID(SER_MAJOR,SER_0_MINOR)
#define HD0	DEV_ID(IDE_MAJOR,0)

const struct ramfs_ino t_ramfs_ino[] = {
 {0,  0, -1,  1, "/"   , 0  , 755, FS_DIR          , 0                      , NULL  }, 
 {1,  0,  3,  2, "dev" , 0  , 755, FS_DIR          , 0                      , NULL  }, 
 {2,  1,  4, -1, "tty" , TTY, 644, FS_FILE|FS_CHAR , 0                      , NULL  }, 
 {3,  0,  6, -1, "init", 0  , 755, FS_FILE         , sizeof(task2)          , task2 }, 
 {4,  1, -1, -1, "hd0" , HD0, 644, FS_FILE|FS_BLOCK, 0                      , NULL  }, 
 {6,  0, -1, -1, "mnt" , 0  , 755, FS_DIR          , 0                      , NULL  },
 
 {-1,-1,-1,-1,"\0",0,0,0,0,NULL}
};

const struct ramfs_super t_ramfs_super = {
	sizeof(t_ramfs_ino)/sizeof(struct ramfs_ino *)-1, &t_ramfs_ino[0]
};

__attribute__((nonnull)) ssize_t ramfs_read(struct fileh *const f, char *const dst, const size_t reqlen, const off_t from)
{
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
		printf("ramfs_read: file dir\n");
		return -EBADF;
	} else if((ino->flags & (FS_FILE|FS_CHAR)) == (FS_FILE|FS_CHAR)) {
		printf("ramfs_read: file char\n");
		return -EBADF;
	} else if((ino->flags & (FS_FILE|FS_BLOCK)) == (FS_FILE|FS_BLOCK)) {
		printf("ramfs_read: file block\n");
		return -EBADF;
	} else if((ino->flags & FS_FILE) == FS_FILE) {
		if(f->flags & FS_KERNEL) {
			/* FIXME - bounds checking*/
			//printf("ramfs_read: %p -> %p len=%lx\n", (void *)src, (void *)dst, len);
			memcpy(dst, src, len);
			//printf("ramfs_read: done\n");
		} else {
			printf("ramfs_read: copy_to_user\n");
			copy_to_user((uint8_t *)dst, f->task, ino->data, len);
		}
	} else {
		printf("ramfs_read: unknown file type\n");
		return -EBADF;
	}
	return len;
}

__attribute__((nonnull)) ssize_t ramfs_write(struct fileh *f, const char *src, size_t len, off_t from)
{

	if (len == 0)
		return 0;

	const struct ramfs_ino *ino = (const struct ramfs_ino *)f->inode->priv;

	//printf("ramfs_write: %x len %x\n", src, len);

	if(ino->flags & FS_DIR) {
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

__attribute__((nonnull(2))) static int ramfs_close(
		__attribute__((unused)) struct task *const t, 
		struct fileh *const fh)
{
	fh->inode->priv = NULL;

	return 0;
}

__attribute__((nonnull(2,3,7)))
static ino_t ramfs_create(struct task *const t, struct mount *const m, struct fileh *const f, 
		const int fl, const mode_t md, const dev_t rdev, void **const p)
{
	//printf("ramfs_create: called\n");
	*p = NULL;
	return -EPERM;
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
		if (t_ramfs_ino[i].ino == -1LL) {
			found = true;
		} else if (!(strcmp(t_ramfs_ino[i].name, fsent->name))) {
			ret = &t_ramfs_ino[i];
			found = true;
		} else {
			i++;
		}
	} while (!found);

	if(!ret) {
		//printf("ramfs_open: no such file: %s\n", file);
		return -ENOENT;
	}

	if ( !(ret->flags & (FS_CHAR|FS_BLOCK)) && (flags & (O_CREAT|O_WRONLY|O_RDWR)) )
		return -EACCES;

	//printf("ramfs_open: setting priv to %p\n", (void*)ret);
	*priv = (void *)ret;

	return i;
}

__attribute__((nonnull)) static int ramfs_mount(struct mount *mnt)
{
	mnt->super = (void *)&t_ramfs_super;
	return 0;
}

__attribute__((nonnull)) static int ramfs_umount(
		__attribute__((unused)) struct mount *const mnt
		)
{
	return 0;
}

__attribute__((nonnull(2))) static int ramfs_ioctl(
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

__attribute__((nonnull)) static int ramfs_sync_inode(struct inode *const inode, const ino_t ino, const int mode)
{
	struct ramfs_ino *rfs_ino;

	//printf("ramfs_sync_inode\n");

    if(mode != SYNC_READ) {
        return 0;
    }

	if(inode->priv == NULL) {
		for(int i = 0; t_ramfs_ino[i].ino != -1LL; i++)
			if(t_ramfs_ino[i].ino == ino) {
				inode->priv = (void *)&t_ramfs_ino[i];
				break;
			}
	}

	rfs_ino = (struct ramfs_ino *)inode->priv;

	if(rfs_ino == NULL)
		return -1;

	inode->st_dev  = inode->mnt->dev->devid;
	inode->st_ino  = rfs_ino->ino;
	inode->st_rdev = rfs_ino->special;
	inode->st_size = rfs_ino->len;
	inode->flags   = rfs_ino->flags;
	inode->st_uid  = 0;
	inode->st_gid  = 0;
	inode->st_mode = rfs_ino->perms;

	return 0;
}

__attribute__((nonnull)) static int ramfs_sync_fsent(struct fsent *fsent, const int mode)
{
	printf("ramfs_sync_fsent: %ld\n", fsent->ino);

    if(mode != SYNC_READ)
        return 0;

	strcpy((char *)fsent->name, t_ramfs_ino[fsent->ino].name);
	fsent->sibling_ino = t_ramfs_ino[fsent->ino].nexti;
	fsent->child_ino = t_ramfs_ino[fsent->ino].childi;
	fsent->flags = t_ramfs_ino[fsent->ino].flags;

	/* TODO */

    return 0;
}

__attribute__((nonnull(2,4,5))) static int ramfs_find(
		__attribute__((unused)) struct task *const tsk, 
		struct mount *const mnt, 
		struct fsent *const cwd,
		const char *const file, 
		struct fsent **ret)
{
	int rc = -ENOENT;
	ino_t parent_ino = cwd ? cwd->ino : 0;
	*ret = NULL;

	printf("ramfs_find: %s\n", file);

	for(int i = 0; t_ramfs_ino[i].ino != -1; i++)
	{
		if(t_ramfs_ino[i].parenti != parent_ino)
			continue;

		if(strcmp(file, t_ramfs_ino[i].name))
			continue;

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
};


