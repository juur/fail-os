#include "klibc.h"
#include "file.h"
#include "block.h"
#include "mem.h"
#include "dev.h"

#define FAILFS_C
#ifndef _KERNEL
#define _KERNEL
#endif
#include "failfs.h"

extern time_t sys_time(void *);

__attribute__((nonnull)) static ssize_t failfs_read(struct fileh *f, char *dst, size_t len, off_t from)
{
	ssize_t bytes_read, bytes_left, rc;
	off_t offset;
	char *buf, *ptr;
	ffs_data_block *dblk;
	const struct block_ops *bops;

	if((buf = kmalloc(f->inode->st_blksize, "buf", NULL, 0)) == NULL) {
		rc = -ENOMEM;
		goto fail;
	}

	bops       = f->inode->mnt->dev->ops;
	dblk       = (ffs_data_block *)buf;
	ino_t next = ((ffs_file_block *)f->inode->priv)->data;
	ptr        = dst;
	bytes_read = 0;
	bytes_left = len;
	offset     = 0;

	do {
		if((rc = bops->read_one(f->inode->mnt->dev, buf, next)) < 0)
			goto fail;

		if(dblk->block_type != FFS_BT_DATA) {
			rc = -EFAULT;
			printf("failfs_read: corruption in data block\n");
			goto fail;
		}

		off_t blk_off, to_copy;

		/* nothing in this block reaches the start */
		if((offset + dblk->len) < from) {
			offset += dblk->len;
			continue;
		}

		/* do we have partial block start?         */
		if(offset < from)
			blk_off = from - offset;
		else
			blk_off = 0;


		/* do we have a partial block end?         */
		if(bytes_left < (dblk->len - blk_off))
			to_copy = bytes_left;
		else
			to_copy = (dblk->len - blk_off);

		/* copy the (partial) block                */
		memcpy(ptr, (dblk->data + blk_off), to_copy);

		ptr        += to_copy;
		bytes_read += to_copy;
		bytes_left -= to_copy;

		offset     += to_copy;
		/* f->seek updated by do_read */

	} while(bytes_left>0 && (next = dblk->next));

	rc = bytes_read;

fail:
	if(buf) 
		kfree(buf);
	return rc;
}

static inline int num_of_set_bit64(uint64_t i)
{
	i = i - ((i >> 1) & 0x5555555555555555UL);
	i = (i & 0x3333333333333333UL) + ((i >> 2) & 0x3333333333333333UL);
	return (int)((((i + (i >> 4)) & 0xF0F0F0F0F0F0F0FUL) * 0x101010101010101UL) >> 56);
}

static inline int first_zero_bit(uint64_t i)
{
	i = ~i;
	return num_of_set_bit64((i&(-i))-1);
}

static ino_t find_free_inode(struct mount *const mnt)
{
	struct failfs_private *ffs = mnt->super;

	for(uint64_t i = 0; i < ffs->free_cnt; i++)
		if(ffs->free_block[i] != ~(0UL)) {
			return (i*64) + first_zero_bit(ffs->free_block[i]);
		}
	return 0;
}

__attribute__((nonnull))
static ssize_t failfs_write(_Unused struct fileh *f, _Unused const char *src, _Unused size_t len, _Unused off_t from)
{
	return -1L;
}

__attribute__((nonnull(2,3,4,7))) 
static ino_t failfs_open(_Unused struct task *const t,_Unused  struct mount *const mnt,struct fsent *const file,
		_Unused struct fileh *const fh,_Unused  const int flags, _Unused const mode_t mode, void **priv)
{
	*priv = NULL;
	return file->ino;
}

__attribute__((nonnull)) 
static int sync_free_block(const struct failfs_private *const p, struct block_dev *const dev)
{
	ffs_free_block **fb;
	int rc = 0;
	const int fb_len = (p->super.block_size - sizeof(ffs_free_block));
	const int num_fb = p->super.num_blocks / (fb_len * 64);

	if( (fb = kmalloc(num_fb * sizeof(ffs_free_block *),"fb",NULL,KMF_ZERO)) == NULL ) {
		rc = -ENOMEM;
		goto fail;
	}

	for( int i = 0; i < num_fb; i++ )
	{
		if ( (fb[i] = kmalloc(sizeof(ffs_free_block) + fb_len,"fb_ent",NULL,0)) == NULL ) {
			rc = -ENOMEM;
			goto fail;
		}

		*fb[i] = (ffs_free_block){
			.magic = "FAILFS",
				.block_type = FFS_BT_FREE,
				.len = fb_len,
				.next = (i + 1 == num_fb) ? 0 : p->super.free_block + i + 1,
				.prev = (i == 0) ? 0 : p->super.free_block + i - 1,
				.flags = 0
		};
	}

	const char *tmp = (const char *)(p->free_block);

	for( int i = 0; i < num_fb; i++, tmp += fb_len )
		memcpy(fb[i]->data, tmp, fb_len);

	for( int i = 0; i < num_fb; i++ )
		if((rc = dev->ops->write_one(dev, (const char *)fb[i], p->super.free_block + i)) < 0)
			goto fail;

fail:
	if(fb) {
		for( int i = 0; i < num_fb; i++ )
			if(fb[i]) 
				kfree(fb[i]);
		kfree(fb);
	}

	return rc;
}

/* S_IFDIR */
__attribute__((nonnull(2,3,4)))
static ino_t failfs_mkdir(struct task *const t, struct mount *mnt, struct fsent *cwd,
		const char *name, mode_t mode)
{
	ffs_file_block *ffb = NULL;
	void *buf   = NULL;
    struct failfs_private *ffspriv = mnt->super;
	ino_t ino = -ENOSYS;
	int rc = 0;

	if((ino = find_free_inode(mnt)) <= 0) {
		ino = ENOSPC;
		goto fail;
	}

	if((ffb = buf = kmalloc(mnt->dev->bsize, "buf", NULL, KMF_ZERO)) == NULL) {
		ino = -ENOMEM;
		goto fail;
	}

	memcpy(ffb->magic, ffs_magic, 6);

	ffb->block_type = FFS_BT_FILE;
	ffb->type       = FFS_FT_DIR;
	ffb->perms      = mode & 0777;
	ffb->owner      = t ? t->euid : 0;
	ffb->group      = t ? t->egid : 0;
	ffb->atime      = sys_time(NULL);
	ffb->ctime      = sys_time(NULL);
	ffb->mtime      = sys_time(NULL);
	if(cwd->fs->dev->devid == mnt->dev->devid)
		ffb->parent     = cwd->ino;
	ffb->child      = NULL_INO;
	ffb->nlink		= 1;
	strncpy(ffb->name, name, 128);

	if((rc = mnt->dev->ops->write_one(mnt->dev, buf, ino)) < 0) {
		ino = rc;
		goto fail;
	}

	ffspriv->free_block[ino/64] |= (1 << (ino & 0x3F));

	if((rc = sync_free_block(mnt->super, mnt->dev)) < 0) {
		printf("failfs_mkdir: unable to sync superblock to disk: %d: %s\n", rc, strerror(rc));
		ffspriv->free_block[ino/64] &= ~(1 << (ino & 0x3F));
	}

fail:
	if(buf)
		kfree(buf);

	return (ino == 0) ? -ENOSPC : ino;
}

/* S_IFREG|S_IFBLK|S_IFCHR */
__attribute__((nonnull(2,3,7))) 
static ino_t failfs_create(struct task *const t, struct mount *const mnt,
		_Unused struct fileh *const fh, _Unused const int flags, 
		const mode_t mode, const dev_t rdev, _Unused void **priv)
{
	ino_t n_ino = NULL_INO;
	int rc      = 0;
	void *buf   = NULL;
	ffs_file_block *ffb = NULL;
    struct failfs_private *ffspriv = mnt->super;

	if(S_ISDIR(mode)) {
		return -EISDIR;
		goto fail;
	}

	if((n_ino = find_free_inode(mnt)) <= 0) {
		n_ino = -ENOSPC;
		goto fail;
	}

	printf("failfs_create: n_ino=%ld\n", n_ino);

	if((ffb = buf = kmalloc(mnt->dev->bsize, "buf", NULL, KMF_ZERO)) == NULL) {
		n_ino = -ENOMEM;
		goto fail;
	}

	memcpy(ffb->magic, ffs_magic, 6);

	ffb->block_type = FFS_BT_FILE;
	ffb->type       = FFS_FT_NORMAL;
	ffb->perms      = mode & 07777;
	ffb->owner      = t ? t->euid : 0;
	ffb->group      = t ? t->egid : 0;
	ffb->atime      = sys_time(NULL);
	ffb->ctime      = sys_time(NULL);
	ffb->mtime      = sys_time(NULL);

	if(S_ISBLK(mode) || S_ISCHR(mode)) {
		ffb->minor = DEV_MAJOR(rdev);
		ffb->minor = DEV_MINOR(rdev);
	}

	if((rc = mnt->dev->ops->write_one(mnt->dev, buf, n_ino)) < 0) {
		n_ino = rc;
		goto fail;
	}

	ffspriv->free_block[n_ino/64] |= (1 << (n_ino & 0x3F));

	if((rc = sync_free_block(mnt->super, mnt->dev)) < 0) {
		printf("failfs_create: unable to sync superblock to disk: %d: %s\n", rc, strerror(rc));
        ffspriv->free_block[n_ino/64] &= ~(1 << (n_ino & 0x3F));
    }

fail:
	if(buf) 
		kfree(buf);

	return (n_ino == NULL_INO) ? -ENOSPC : n_ino;
}

__attribute__((nonnull(2)))
static int failfs_close(_Unused struct task *t,_Unused struct fileh *fh)
{
	return 0;
}

__attribute__((nonnull))
static int failfs_sync_fsent(struct fsent *const fsent, const int mode)
{
	void *buf;
    int rc = 0;
	ino_t ino;
    struct failfs_private *priv = fsent->fs->super;

	ino = fsent->ino;
	printf("failfs_sync_fsent: ino=%ld mode=%d\n", ino, mode);

    if(ino <= 0 || (ino >= priv->super.free_block && ino < priv->first_normal_block)) {
		printf("failfs_sync_fsent: attempt to sync super or free block as an inode: %ld\n", fsent->ino);
        return -EINVAL;
	}

	if((buf = kmalloc(fsent->fs->dev->bsize, "buf", NULL, 0)) == NULL) {
		return -ENOMEM;
	}

    switch(mode) {
        case SYNC_READ:
            {
				ffs_file_block *blk = buf;

				if((rc = fsent->fs->dev->ops->read_one(fsent->fs->dev, buf, fsent->ino)) < 0)
					goto fail;

				if(strncmp((const char *)blk->magic, (const char *)ffs_magic, 6)) {
					printf("failfs_sync_fsent: magic mistmatch\n");
					rc = -EINVAL;
					goto fail;
				}

				if(blk->block_type != FFS_BT_FILE) {
					printf("failfs_sync_fsent: not a file\n");
					rc = -EINVAL;
					goto fail;
				}

				if(blk->type != FFS_FT_LINK && blk->type != FFS_FT_DIR) {
					printf("failfs_sync_fsent: not a link\n");
					rc = -EINVAL;
					goto fail;
				}

				/* TODO how to handle parent, sibling & child */
				strncpy((char *)fsent->name, blk->name, 128);

				fsent->sibling_ino = blk->next;
				fsent->child_ino   = blk->child;
				rc = 0;
            }
            break;

        case SYNC_WRITE:
			{
				ffs_file_block *blk = buf;

				memcpy(blk->magic, ffs_magic, 6);
				strncpy(blk->name, fsent->name, 128);

				blk->block_type  = FFS_BT_FILE;
				blk->type        = FFS_FT_LINK;

				if(fsent->parent && fsent->parent->fs != fsent->fs) {
					blk->parent = fsent->parent->ino;
				} else
					blk->parent = priv->super.root_block;

				if(fsent->next && fsent->next->fs != fsent->fs) {
					blk->next = fsent->next->ino;
				} else
					blk->next = NULL_INO;

				if(fsent->child && fsent->child->fs != fsent->fs) {
					blk->child = fsent->child->ino;
				} else
					blk->child = NULL_INO;

				blk->target = fsent->inode->st_ino; /* TODO how do we ensure !NULL ? */

                if((rc = fsent->fs->dev->ops->write_one(fsent->fs->dev, buf, fsent->ino)) < 0)
                    goto fail;

				rc = 0;
			}
            break;

        default:
            printf("failfs_sync_fsent: unknown sync mode: %d\n", mode);
            rc = -EINVAL;
            goto fail;
    }

fail:
	if(buf)
		kfree(buf);

	return rc;
}

/* S_IFLNK */
__attribute__((nonnull(2))) 
static int failfs_link(_Unused struct task *const tsk, struct fsent *const fsent, const ino_t ino)
{
	int rc                      = 0;
	ino_t blk                   = 0;
	void *buf                   = NULL;
	ffs_file_block *ffb         = NULL;
	struct mount *mnt           = fsent->fs;
	struct failfs_private *priv = mnt->super;

	if((rc = blk = find_free_inode(mnt)) < 0)
		goto fail;

	if((ffb = buf = kmalloc(mnt->dev->bsize, "buf", NULL, KMF_ZERO)) == NULL) {
		rc = -ENOMEM;
		goto fail;
	}

	memcpy(ffb->magic, ffs_magic, 6);
	strncpy(ffb->name, fsent->name, 128);

	ffb->block_type  = FFS_BT_FILE;
	ffb->type        = FFS_FT_LINK;
	ffb->parent = fsent->parent  ? fsent->parent->ino  : priv->super.root_block;
	ffb->next   = fsent->sibling ? fsent->sibling->ino : NULL_INO;
	ffb->child  = NULL_INO;
	ffb->target = ino;

	if((rc = mnt->dev->ops->write_one(mnt->dev, buf, blk)) < 0)
		goto fail;

	priv->free_block[blk/64] |= (1 << (blk & 0x3F));

	if((rc = sync_free_block(mnt->super, mnt->dev)) < 0) {
		printf("failfs_link: unable to sync superblock to disk: %d: %s\n", rc, strerror(rc));
        priv->free_block[blk/64] &= ~(1 << (blk & 0x3F));
    }

	rc = 0;

fail:
	if(ffb) 
        kfree(ffb);

	return rc;
}

__attribute__((nonnull))
static int failfs_sync_inode(struct inode *const inode, const ino_t ino, const int mode)
{
	printf("failfs_sync_inode: block:%ld %s\n", ino, (mode == SYNC_READ) ? "READ" : "WRITE");

    struct failfs_private *priv = inode->mnt->super;
	char *buf;
	int rc = 0;

    if(ino <= 0 || (ino >= priv->super.free_block && ino < priv->first_normal_block)) {
		printf("failfs_sync_inode: attempt to sync super or free block as an inode: %ld\n", ino);
        return -EBADF;
	}

	if((buf = kmalloc(inode->mnt->dev->bsize, "buf", NULL, 0)) == NULL) {
		return -ENOMEM;
	}

	switch(mode)
	{
		case SYNC_WRITE:
			{
				if(!inode->priv && (rc = failfs_sync_inode(inode, ino, SYNC_READ)) < 0)
					goto fail;

				ffs_file_block *blk = inode->priv;
				
				blk->perms   = inode->st_mode;
				blk->nlink   = inode->st_nlink;
				blk->owner   = inode->st_uid;
				blk->group   = inode->st_gid;
				blk->minor	 = DEV_MINOR(inode->st_rdev);
				blk->major	 = DEV_MAJOR(inode->st_rdev);
				blk->size    = inode->st_size;
				blk->atime	 = inode->st_atime;
				blk->ctime	 = inode->st_ctime;
				blk->mtime	 = inode->st_mtime;

				*(ffs_file_block *)buf = *blk;

				if((rc = inode->mnt->dev->ops->write_one(inode->mnt->dev, buf, ino)) < 0)
					goto fail;
			}
			break;

		case SYNC_READ:
			{
				/* TODO check for valid inode */
				if((rc = inode->mnt->dev->ops->read_one(inode->mnt->dev, buf, ino)) < 0)
					goto fail;

				ffs_file_block blk = *(ffs_file_block *)buf;

				if(blk.block_type != FFS_BT_FILE) {
					rc = -EBADF;
					goto fail;
				}

				if(inode->priv)
					kfree(inode->priv);

				inode->st_ino     = ino;
				inode->st_dev     = inode->mnt->dev->devid;
				inode->st_mode    = blk.perms;
				inode->st_nlink   = blk.nlink;
				inode->st_uid     = blk.owner;
				inode->st_gid     = blk.group;
				inode->st_rdev    = DEV_ID(blk.major,blk.minor);
				inode->st_size    = blk.size;
				inode->st_blksize = inode->mnt->dev->bsize;
				inode->st_blocks  = blk.size / inode->st_blksize;
				inode->st_atime   = blk.atime;
				inode->st_ctime   = blk.ctime;
				inode->st_mtime   = blk.mtime;

				/* we don't kfree(buf) as it's now inode->priv */
				buf = NULL;
			}
			break;

		default:
			printf("failfs_sync_inode: unknown sync mode: %d\n", mode);
			rc = -EINVAL;
			goto fail;
	}

fail:
	if(buf)
		kfree(buf);
	return rc;
}

__attribute__((nonnull))
static void dump_fb(const struct failfs_private *const fb)
{
	uint32_t i = 0;

	for(uint32_t j = 0; j < fb->free_cnt; j++)
		if(fb->free_block[j])
			i += popcountll(fb->free_block[j]);

	printf("failfs_dump_fb: %u/%u blocks used (%lu free entries)\n", 
			i, 
			fb->super.num_blocks, 
			fb->free_cnt);
}

__attribute__((nonnull))
static void dump_sb(const ffs_superblock *const sb)
{
	printf( "failfs_dump_sb: "
			"block_size: %u "
			"num_blocks: %u "
			"\n"
			,
			sb->block_size,
			sb->num_blocks
		  );
}

__attribute__((nonnull))
static void dump_ffb(const ffs_file_block *const ffb)
{
	printf( "failfs_dump_fb: "
			"type: %d "
			"name: %s\n"
			,
			ffb->type,
			ffb->name);
}

__attribute__((nonnull))
static int failfs_umount(struct mount *const mnt)
{
	struct failfs_private *priv = (struct failfs_private *)mnt->super;

	if(priv && priv->free_block) kfree(priv->free_block);
	if(priv) kfree(priv);

	return 0;
}

__attribute__((nonnull))
static int failfs_mount(struct mount *const mnt)
{
	ffs_superblock sb;
	int rc;
	char *buf = NULL;
	struct failfs_private *priv = NULL;

	/*printf("failfs_mount: %p dev:%p [BSIZE=%x]\n", 
			(void *)mnt, 
			(void *)mnt->dev,
			mnt->dev->bsize
		  );*/

	if((buf = kmalloc(mnt->dev->bsize, "buf", NULL, 0)) == NULL)
		return -ENOMEM;

	if((rc = mnt->dev->ops->read_one(mnt->dev, buf, 2)) < 0)
		goto fail;

	memcpy(&sb, buf, sizeof(sb));
	//dump_sb(&sb);

	if((priv = mnt->super = kmalloc(sizeof(struct failfs_private), "failfs_priv", NULL, KMF_ZERO)) == NULL)
		goto fail;

	memcpy(&priv->super, &sb, sizeof(sb));

	if((rc = mnt->dev->ops->read_one(mnt->dev, buf, sb.root_block)) < 0) {
		printf("failfs: failed to read root_block: %d\n", rc);
		goto fail;
	}

	memcpy(&priv->root, buf, sizeof(priv->root));

	/* allocate space for merged array of free block bitfields */
	const int fb_len = (sb.block_size - sizeof(ffs_free_block));		/* size of free_block.data[] */
	const int num_fb = sb.num_blocks / (fb_len * 64);					/* number of free_blocks     */

	/* number of entries in free_block[] */
	priv->free_cnt = sb.num_blocks / 64;

    /* number of free blocks on disk */
    priv->num_free_blocks    = num_fb;
	priv->first_normal_block = sb.free_block + num_fb;

	if((priv->free_block = kmalloc_align((priv->free_cnt * sizeof(uint64_t)), "failfs_freeblock", NULL, 0)) == NULL)
		goto fail;

	/* read all free blocks into memory */
	for(int i = 0; i < num_fb; i++) {
		ffs_free_block *const ffb = (ffs_free_block *)buf;

		//printf("failfs: reading %u\n", sb.free_block + i);
		if((rc = mnt->dev->ops->read_one(mnt->dev, (char *)ffb, sb.free_block + i)) < 0) {
			printf("failfs: failed to read free block: %d\n", rc);
			goto fail;
		}

		/*
		   printf("failfs: sector:%u bsize:%u free_block:%lx src:%lx[%lx] len:%x\n",
		   sb.free_block + i,
		   mnt->dev->bsize,
		   ((uint64_t)priv->free_block + (fb_len * i)),
		   (uint64_t)ffb->data,
		   (uint64_t)ffb,
		   fb_len);
		   */

		memcpy((void *)((uint64_t)priv->free_block + (fb_len * i)), ffb->data, fb_len);
	}

	//dump_fb(priv);

	if(buf) kfree(buf);
	return priv->super.root_block;

fail:
	printf("failfs: fail\n");
	if(buf) kfree(buf);
	if(priv && priv->free_block) kfree(priv->free_block);
	if(priv) kfree(priv);
	mnt->super = NULL;
	return -1;
}

__attribute__((nonnull(2)))
static int failfs_ioctl(_Unused struct task *const t,_Unused struct fileh *const fh, const uint64_t req, ...)
{
	va_list ap;
	va_start(ap, req);
	int rc = -EBADF;

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

__attribute__((nonnull(2,4,5)))
static int failfs_find(_Unused struct task *const tsk, struct mount *const mnt, struct fsent *const cwd,
		const char *const name, struct fsent **ret)
{
	struct failfs_private *priv = (struct failfs_private *)mnt->super;
	ffs_file_block *ffb;
	char *buf = NULL;
	int rc = -ENOENT;
	*ret = NULL;

	printf("failfs_find: %s in %s\n", name, cwd ? cwd->name : "[root]");

	if(cwd == NULL && !strcmp("/", name)) {
		if((*ret = create_fsent(mnt, NULL, priv->super.root_block, &rc, name, false)) == NULL)
			goto fail;
		return priv->super.root_block;
	}

	if((buf = kmalloc(priv->super.block_size, "buf", NULL, 0)) == NULL) {
		rc = -ENOMEM;
		goto fail;
	}

	ino_t cur = cwd ? cwd->ino : priv->super.root_block;
	ffb = (ffs_file_block *)buf;
	printf("failfs_find: about to read %ld\n", cur);
	if((rc = mnt->dev->ops->read_one(mnt->dev, buf, cur)) < 0)
		goto fail;

	dump_ffb(ffb);

	if(ffb->block_type != FFS_BT_FILE) {
		rc = -EINVAL;
		goto fail;
	}

	if(ffb->type == FFS_FT_NORMAL || ffb->type == FFS_FT_DELETED) {
		rc = -EINVAL;
		goto fail;
	}

	cur = ffb->child;
	printf("failfs_find: cur = %ld\n", cur);

	while(cur)
	{
		printf("failfs_find: about to read %ld\n", cur);
		if((rc = mnt->dev->ops->read_one(mnt->dev, buf, cur)) < 0)
			goto fail;

		printf("failfs_find: %s==%s\n", ffb->name, name);

		if(!strcmp(ffb->name, name)) {
			if((*ret = create_fsent(mnt, cwd, cur, &rc, name, false)) == NULL)
				goto fail;
			rc = cur;
			break;
		}

		cur = ffb->next;
	}

	if (cur == 0)
		rc = -ENOENT;

fail:
	if(buf) kfree(buf);
	return rc;
}

const struct fs_ops failfs_ops = {
	"failfs",

	.close      = failfs_close,
	.create     = failfs_create,
	.find       = failfs_find,
	.ioctl      = failfs_ioctl,
	.link       = failfs_link,
	.mount      = failfs_mount,
	.open       = failfs_open,
	.read       = failfs_read,
	.sync_fsent = failfs_sync_fsent,
	.sync_inode = failfs_sync_inode,
	.umount     = failfs_umount,
	.write      = failfs_write,
	.mkdir		= failfs_mkdir,
};
