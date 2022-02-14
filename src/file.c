#include "file.h"
#include "mem.h"
#include "block.h"
#include "dev.h"
#include "proc.h"
#include "net.h"
#include "syscall.h"

struct mount *mounts;
static int mounts_lock;
struct mount *root_mnt;
struct fsent *root_fsent;

static struct inode *inodes;
static int inodes_lock;

static struct fsent *fsents;
static int fsents_lock;

void print_fh(const struct fileh *fh)
{
	printf("fh:\n"
			"\tinode:   %lx [%p]\n"
			"\tspecial: %x\n"
			"\tfs:      %p\n"
			"\tperms:   %x\n"
			"\tflags:   %lx\n"
			"\tdev:     %p\n"
			"\ttask:    %p\n",
			fh->inode->st_ino,
			(void *)fh->inode,
			fh->inode->st_rdev,
			(void *)fh->fs,
			fh->inode->st_mode,
			fh->flags,
			fh->sdev.dev,
			(void *)fh->task);
}

void file_init(void)
{
	mounts      = NULL;
	mounts_lock = 0;
	root_mnt    = NULL;
	root_fsent  = NULL;
	inodes      = NULL;
	inodes_lock = 0;
	fsents      = NULL;
	fsents_lock = 0;
}

__attribute__((nonnull))
static void dump_fsent(struct fsent *const start, const bool children)
{
	struct fsent *tmp;
	struct fsent *i = start;

	printf("fsent: %p [%03ld]{%d,%d}'%20s' lock:%2d", 
			(void *)i,
			i->ino,
			DEV_MAJOR(i->fs->dev->devid),
			DEV_MINOR(i->fs->dev->devid),
            i->name,
			i->count
			);
	if(i->parent && i->parent != i)
		printf(" (parent: [%03ld]{%d,%d}'%20s')",
				i->parent->ino,
				DEV_MAJOR(i->parent->fs->dev->devid),
				DEV_MINOR(i->parent->fs->dev->devid),
                i->parent->name
			  );
	if(i->sibling)
		printf(" (sibling: [%03ld]{%d,%d}'%20s')",
                i->sibling->ino,
				DEV_MAJOR(i->fs->dev->devid),
				DEV_MINOR(i->fs->dev->devid),
				i->sibling->name
				);
	printf("\n");

//    if(i->child_fs) {
//        i = i->child_fs->root;
//	}

	if(children) {
		for(tmp = i->child; tmp; tmp = tmp->sibling) {
			dump_fsent(tmp, true);
		}
	}
}

void dump_fsents()
{
	printf("Dumping fsents:\n");
	spin_lock(&fsents_lock); {
		for(struct fsent *tmp = fsents; tmp; tmp=tmp->next)
			dump_fsent(tmp, false);
	} spin_unlock(&fsents_lock);
}

__attribute__((nonnull))
static void add_inode(struct inode *const i)
{
	//printf("add_inode: %p\n", (void *)i);
	spin_lock(&inodes_lock); {
		i->next = inodes;
		inodes  = i;
	} spin_unlock(&inodes_lock);
}

__attribute__((nonnull))
static void add_fsent(struct fsent *const i)
{
	spin_lock(&fsents_lock); {
		i->next = fsents;
		fsents  = i;
	} spin_unlock(&fsents_lock);
}

__attribute__((nonnull))
static void close_inode(struct inode *const i)
{
	//printf("close_inode: %p\n", (void*)i);

	spin_lock(&i->lock); {
		i->count--;

		/*
		if(i->count == 0) {
			spin_lock(&inodes_lock); {
				for(struct inode *tmp = inodes; tmp; tmp = tmp->next)
					if(tmp->next == i) {
						tmp->next = i->next;
						break;
					}
				if(inodes == i)
					inodes = i->next;
			} spin_unlock(&inodes_lock);

			//printf("close_inode: %p freed\n", (void*)i);
			kfree(i);
			return;
		}
		*/
	} spin_unlock(&i->lock);
}

__attribute__((nonnull)) 
static int free_fsent(struct fsent *const fsent)
{
    if(fsent->flags & FS_DELETED) {
		printf("free_fsent: double delete [%03ld] count:%d\n", fsent->ino, fsent->count);
        return 0;
	}

	spin_lock(&fsent->lock); {
        //if(!--fsent->count) fsent->flags |= FS_DELETED;
		fsent->count--;
		//printf("free_fsent: [%03ld] count:%d\n", fsent->ino, fsent->count);
	}; spin_unlock(&fsent->lock);

	return 0;
}

static void delete_one(struct fsent *ent)
{
	struct fsent *tmp, *next;

	for(tmp = fsents; tmp; tmp = next) {
		next = tmp->next;

		if(next == ent) {
			tmp->next = next->next;
			next      = next->next;
		}
	}

    if(!ent->parent)
        return;

    for(tmp = ent->parent->child; tmp; tmp = next) {
        next = tmp->sibling;

        if(next == ent) {
            tmp->sibling = next->sibling;
            next         = next->sibling;
        }
    }

    kfree(ent);
}

void flush_fsents()
{
	struct fsent *next = NULL;

	spin_lock(&fsents_lock); {
		for(struct fsent *i = fsents; i; i = next) {
			next = i->next;

			if(i->lock || i->count)
				continue;

			spin_lock(&i->lock); {
				if( (i->flags & FS_DELETED) )
					delete_one(i);
				else
					i->flags |= FS_DELETED;
			} spin_unlock(&i->lock);
		}
	} spin_unlock(&fsents_lock);
}

struct fsent *create_fsent(struct mount *const mnt, struct fsent *const parent, ino_t ino, int *const error, const char *const new_name, const bool is_new)
{
	struct fsent *ret = NULL;
	*error = 0;

	if((ret = kmalloc(sizeof(struct fsent), "fsent", NULL, KMF_ZERO)) == NULL) {
		*error = -ENOMEM;
		goto fail;
	}

	ret->parent = parent;
	ret->fs     = mnt;
	ret->ino    = ino;
	ret->count  = 1;

	if(is_new) {
		if(new_name == NULL) {
			*error = -EFAULT;
			goto fail;
		}
		strncpy((char *)ret->name, new_name, NAME_MAX);
	}

	/*
	
	if(parent) {
		spin_lock(&parent->lock); {
			if(!parent->child)
				parent->count++;
			ret->sibling     = parent->child;
			parent->child    = ret;
		} spin_unlock(&parent->lock);
	}

	*/

	add_fsent(ret);

	/* FIXME parent is on different device */
	if(is_new && parent && (*error = mnt->ops->sync_fsent(parent, SYNC_WRITE)) < 0) {
		printf("create_fsent: failed to sync parent: %d: %s\n", *error, strerror(*error));
		goto fail;
	}

	if((*error = mnt->ops->sync_fsent(ret, is_new ? SYNC_WRITE : SYNC_READ)) < 0) {
		printf("create_fsent: failed to sync: %d: %s\n", *error, strerror(*error));
		goto fail;
	}

	/*
	printf("create_fsent: @%p [%ld(%d,%d){%s}]: parent=%ld(%d:%d){%s} parent->child=%ld(%d:%d){%s} sibling=%ld(%d:%d){%s}\n",
			(void *)ret,
			ino, 
			DEV_MAJOR(mnt->dev->devid), 
			DEV_MINOR(mnt->dev->devid),
			ret->name,
			parent ? parent->ino : -1, 
			parent ? DEV_MAJOR(parent->fs->dev->devid) : -1, 
			parent ? DEV_MINOR(parent->fs->dev->devid) : -1,
			parent ? parent->name : "",
			parent && parent->child ? parent->child->ino : -1, 
			parent && parent->child ? DEV_MAJOR(parent->child->fs->dev->devid) : -1,
			parent && parent->child ? DEV_MINOR(parent->child->fs->dev->devid) : -1,
			parent && parent->child ? parent->child->name : "",
			ret->sibling_ino,
			ret->sibling ? DEV_MAJOR(ret->sibling->fs->dev->devid) : -1,
			ret->sibling ? DEV_MINOR(ret->sibling->fs->dev->devid) : -1,
			ret->sibling ? ret->sibling->name : ""

		  );
	*/

	return ret;

fail:
	if(ret)
		free_fsent(ret);

	return NULL;
}

struct inode *open_inode(struct mount *const m, const ino_t inode, int *const error)
{
	struct inode *ret = NULL;

	printf("open_inode: m=%p m->dev=%p inode=%lx dev=(%d,%d)\n", 
			(void *)m,
			(void *)m->dev,
			inode, 
			DEV_MAJOR(m->dev->devid),
			DEV_MINOR(m->dev->devid)
		  );

	spin_lock(&inodes_lock); {
		for(struct inode *tmp = inodes; tmp; tmp = tmp->next)
		{
			if(tmp->st_ino != inode || tmp->st_dev != m->dev->devid)
				continue;

			spin_lock(&tmp->lock); {
				tmp->count++;
			} spin_unlock(&tmp->lock);
			ret = tmp;
			//printf("open_inode: cache hit\n");
			break;
		}
	} spin_unlock(&inodes_lock);

	if(ret) 
		return ret;

	if((ret = kmalloc(sizeof(struct inode), "inode", NULL, KMF_ZERO)) == NULL) {
		*error = -ENOMEM;
		goto fail;
	}

	ret->count++;
	ret->mnt = m;
	if(m->ops->sync_inode(ret, inode, SYNC_READ) < 0)
		goto fail;

	add_inode(ret);

	return ret;

fail:
	if(ret)
		kfree(ret);
	return NULL;
}

	__attribute__((nonnull(1)))
static int access_check(struct fileh *const fh, struct task *const tsk, const int flags)
{
	if(!tsk)
		return 0; /* kernel always succeeds */

    if(fh->flags & FS_KERNEL)
        return -EPERM;

    if(tsk->euid == 0)
        return 0; /* root always succeeds   */

    bool ret = -EPERM;

    const uid_t  u = tsk->euid;
    const gid_t  g = tsk->egid;
    const uid_t fu = fh->inode->st_uid;
    const gid_t fg = fh->inode->st_gid;
    const mode_t m = fh->inode->st_mode;

    if       ((fh->flags & FS_FILE) && (flags & (O_RDWR|O_WRONLY))) {
        if     (u == fu && (m & S_IWUSR)) ret = 0;
        else if(g == fg && (m & S_IWGRP)) ret = 0;
        else if(           (m & S_IWOTH)) ret = 0;
    } else if((fh->flags & FS_FILE) && (flags & (O_RDONLY))) {
        if     (u == fu && (m & S_IRUSR)) ret = 0;
        else if(g == fg && (m & S_IRGRP)) ret = 0;
        else if(           (m & S_IROTH)) ret = 0;
    } else if((fh->flags & FS_DIR)) {
        if     (u == fu && (m & S_IXUSR)) ret = 0;
        else if(g == fg && (m & S_IXGRP)) ret = 0;
        else if(           (m & S_IXOTH)) ret = 0;
    }

	return ret;
}

__attribute__((nonnull))
static struct fsent *find_or_create(struct mount *mnt, struct fsent *cwd, ino_t ino)
{
	struct fsent *ret = NULL, *tmp;
	int dummy_error;

	printf("find_or_create: on=(%d,%d) ino=%ld\n", 
			DEV_MAJOR(mnt->dev->devid),
			DEV_MINOR(mnt->dev->devid),
			ino);

	spin_lock(&fsents_lock); {
		for(tmp = fsents; tmp; tmp = tmp->next)
		{
			if(tmp->ino == ino && tmp->fs == mnt ) {
				printf("find_or_create: found: %s\n", ret->name);
				ret = tmp;
				break;
			}
		}
	}; spin_unlock(&fsents_lock);
	if(ret) goto fail;

	ret = create_fsent(mnt, cwd, ino, &dummy_error, NULL, false);
	printf("find_or_create: created: %s[%ld]{s:%ld}\n", ret ? ret->name : "FAILED", ino, ret->sibling_ino);

fail:
	return ret;
}

__attribute__((nonnull))
static void populate_dir(struct fsent *const cwd)
{
	printf("populate_dir: cwd.child_ino=%ld cwd.name=%s\n", cwd->child_ino, cwd->name);

	if(!cwd->child_ino)
		return;

	/*
	struct mount *where = child_fs ? cwd->child_fs : cwd->fs;
	struct fsent *root  = cwd->child_fs ? where->root   : cwd;
	*/
	
	struct mount *where = cwd->fs;
	struct fsent *root  = cwd;

	printf("populate_dir: create root->child\n");
	root->child = find_or_create(where, root, cwd->child_ino);

	if(!root->child) {
		printf("populate_dir: is not a directory (no children)\n");
		return;
	}

	struct fsent *tmp = root->child;
	ino_t tmpi = tmp->sibling_ino;

	if(tmp && tmpi>0)
		printf("populate_dir: creating siblings\n");
	else
		printf("populate_dir: no siblings '%p' %ld\n", tmp, tmpi);

	for(; tmp && tmpi>0; )
	{
		tmp->sibling = find_or_create(where, root, tmpi);
		tmp = tmp->sibling;
		tmpi = tmp->sibling_ino;
		printf("populate_dir: added\n");
	}
	tmp->sibling = NULL; // FIXME
	printf("populate_dir: done\n");
}

__attribute__((nonnull))
static struct fsent *find_fsent(struct fsent *const cwd, const char *const name, int *const error)
{
	struct fsent *ret = NULL;
	*error            = 0;

	printf("find_fsent: cwd=%s(%d,%d) name=%s\n", 
			cwd->name,
			DEV_MAJOR(cwd->fs->dev->devid),
			DEV_MINOR(cwd->fs->dev->devid),
			name);
	
	if(!cwd->child)
		populate_dir(cwd);

	for(ret = cwd->child; ret; ret = ret->sibling) {
		printf("find_fsent: checking ino=%ld [%s][%d]\n", ret->ino, ret->name, ret->flags & FS_DELETED);
		//printf("find_fsent: %ld\n", !(ret->flags & FS_DELETED));
		//printf("find_fsent: '%s'=='%s' %ld\n", name, ret->name, !strcmp(name, ret->name));

		if(!(ret->flags & FS_DELETED) && !strcmp(name, ret->name)) {
			printf("find_fsent: found: ino: %ld\n", ret->ino);
			return ret;
		}
	}
	printf("find_fsent: failed\n");

	return NULL;
}

/* TODO add a cwd */
struct fsent *resolve_file(const char *const name, struct fsent *const cwd, int *const error)
{
	struct fsent *cur, *tmpi;
	char *oldpart, *part, *saveptr, *fn;

	*error = -ENOENT;

	cur = cwd ? cwd : root_fsent;

	if((fn = strdup(name)) == NULL) {
		*error = -ENOMEM;
		goto fail;
	}

	printf("resolve_file: %s\n", name);

	oldpart = fn;
	part = strtok_r(fn, "/", &saveptr);

	bool running = true;

	while(running && cur && part)
	{
		//printf("part:%s oldpart:%s\n", part, oldpart);

		if(part == NULL) {
			part = oldpart;
			running = false;
		}
		
		if(!strcmp(".", part))
			goto next;

        /* handle case of root filesystem on a mount point */
		if(!strcmp("..", part)) {
            if(cur->flags & FS_MOUNTED)
                cur = cur->fs->point;
            else
                cur = cur->parent;
			goto next;
		}

		//struct mount *where;
		
		/* FIXME */
		//if(cur->child_fs)
		//	cur = cur->child_fs->root;

		//where = cur->fs;

		if((tmpi = find_fsent(cur, part, error)) == NULL && *error)
			goto fail;
		else if(tmpi != NULL)
			cur = tmpi;
		/*else if((*error = cur->fs->ops->find(NULL, where, cur, part, &cur)) < 0)
			goto fail;*/
next:
		oldpart = part;
		part = strtok_r(NULL, "/", &saveptr);
	}

	if(cur == NULL)
		goto fail;

	if(fn) 
		kfree(fn);

	//printf("resolve_file: OK\n");
	*error = 0;
	return cur;

fail:
	//printf("resolve_file: FAIL: %s\n", strerror(*error));
	if(fn) 
		kfree(fn);
	return NULL;
}

__attribute__((nonnull(3,4,6)))
static int create_link(struct task *const tsk, struct fsent *const cwd, const char *name, struct mount *const mnt, const ino_t dest, struct fsent **ret)
{
	struct fsent *new_name = NULL;
	int error = 0;

	if((new_name = create_fsent(mnt, cwd, dest, &error, name, true)) == NULL)
		goto fail;

	if((error = mnt->ops->link(tsk, new_name, dest)) < 0)
		goto fail;

	*ret = new_name;

	return 0;
fail:
	if(new_name)
		free_fsent(new_name);

	return error;
}

struct mount *do_mount(struct block_dev *const dev, struct fsent *const point, const struct fs_ops *const fsops)
{
	struct mount *mnt;
	int error;
	ino_t root_inode;
	
	if((mnt = kmalloc(sizeof(struct mount), "mount", NULL, KMF_ZERO)) == NULL)
		return NULL;

	//printf("do_mount: [%lx] on '%s' type '%s'\n", dev ? dev->devid : 0, point, &fsops->name[0]);

	mnt->dev   = dev;
	mnt->ops   = fsops;
	mnt->super = NULL;
	mnt->point = point;

	if((root_inode = fsops->mount(mnt)) < 0) {
		printf("do_mount: fs mount failed: %ld: %s\n", root_inode, strerror(root_inode));
		goto fail;
	}

	if((error = fsops->find(NULL, mnt, NULL, "/", &mnt->root)) < 0) {
		printf("do_mount: find failed: %d: %s\n", error, strerror(error));
		goto fail;
	}

	mnt->root->count++;
    mnt->root->flags |= FS_MOUNTED;

	if(point) {
		point->count++;
		/* FIXME FIXME this is wrong completely */
		//point->child_fs = mnt;
		point->fs = mnt;
	}

	spin_lock(&mounts_lock); {
        mnt->next = mounts;
        mounts    = mnt;
	}; spin_unlock(&mounts_lock);

	return mnt;

fail:
	if(mnt && root_inode) fsops->umount(mnt);
	if(mnt) kfree(mnt);
	return NULL;
}

ssize_t do_write(struct fileh *const fh, const char *const src, const size_t len)
{
	//printf("do_write: fh:%lx is_valid:%x\n", fh, src);
	//print_fh(fh);
	//printf("do_write: fh:%lx from:%lx len:%lx\n", fh, src, len);
	
	ssize_t rc;
	
	if((fh->inode->flags & FS_CHAR) == FS_CHAR) {
		if(fh->sdev.char_dev && fh->sdev.char_dev->ops &&fh->sdev.char_dev->ops->write) {
			return fh->sdev.char_dev->ops->write(fh->sdev.char_dev, src, len);
		} else {
			printf("do_write: sdev is NULL!\n");
			hlt();
			return -1;
		}
	} else if( (fh->flags & FS_SOCKET) == FS_SOCKET ) {
		// printf("socket\n");
		return 0;
	} else {
		if((fh->flags & O_APPEND) == O_APPEND)
			do_lseek(fh, 0, SEEK_END);
		if((rc = fh->fs->ops->write(fh, src, len, fh->seek)) > 0)
			fh->seek += rc;
		return rc;
	}
}

ssize_t do_read(struct fileh *const fh, char *const dst, const size_t len)
{
	ssize_t ret = 0;

	//printf("do_read: %lx - %lx [%lx]\n", dst, dst+len, len);
	
	if((fh->inode->flags & FS_CHAR) == FS_CHAR) {
		//printf("do_read: special char\n");
		if(fh->sdev.char_dev && fh->sdev.char_dev->ops && fh->sdev.char_dev->ops->read)
			ret = fh->sdev.char_dev->ops->read(fh->sdev.char_dev, dst, len);
		else {
			printf("do_read: sdev is NULL\n");
			hlt();
			return -1;
		}
		//printf("do_read: ret:%lx\n", ret);
	} else if((fh->inode->flags & FS_BLOCK) == FS_BLOCK) {
		//printf("do_read: special block\n");
		ret = fh->sdev.blk_dev->ops->read(fh->sdev.blk_dev, dst, len, 
				fh->seek);
	} else if( fh->flags & FS_SOCKET ) {
		printf("do_read socket\n");
		ret = 0;
	} else {
		//printf("do_read: file\n");
		if((ret = fh->fs->ops->read(fh, dst, len, fh->seek)) > 0)
			fh->seek += ret;
	}

	return ret;
}

int do_mkdir(struct task *const tsk, const char *pathname, const mode_t mode)
{
	struct fsent *fsent     = NULL;
	struct fsent *new_fsent = NULL;
	int error               = -EEXIST;
	char *dir               = NULL;
	char *base              = NULL;
	struct mount *where     = NULL;
	ino_t new_ino;

    //printf("do_mkdir: %s %d\n", pathname, mode);

	if((fsent = resolve_file(pathname, NULL, &error)) != NULL)
        goto fail;

	if((error != -ENOENT))
        goto fail;

	if((dir = dirname(pathname)) == NULL)
		goto fail;

	if((base = basename(pathname)) == NULL)
		goto fail;

    //printf("do_mkdir: dir=%s base=%s\n", dir, base);

	if((fsent = resolve_file(dir, NULL, &error)) == NULL)
		goto fail;

    /* move the cursor to the fsent on the target fs */
	/* FIXME */
    //if(fsent->child_fs) {
    //    fsent = fsent->child_fs->root;
    //}

    where = fsent->fs;

    //printf("do_mkdir: mkdir in %s (%d,%d)\n", where->ops->name, DEV_MAJOR(where->dev->devid), DEV_MINOR(where->dev->devid));
	if((error = new_ino = where->ops->mkdir(tsk, where, fsent, base, mode)) < 0)
		goto fail;

    //printf("do_mkdir: new_ino=%ld\n", new_ino);

	if((new_fsent = create_fsent(where, fsent, new_ino, &error, base, false)) == NULL) {
		goto fail;
	}

	if((error = fsent->fs->ops->sync_fsent(fsent, SYNC_WRITE)) < 0)
		goto fail;

	if((error = new_fsent->fs->ops->sync_fsent(new_fsent, SYNC_WRITE)) < 0)
		goto fail;

fail:
	if(dir) 
		kfree(dir);

	if(base) 
		kfree(base);

    if(error < 0 && new_fsent)
        free_fsent(new_fsent);

	return error;
}

off_t do_lseek(struct fileh *const fh, const off_t off, const int whence)
{
	if( (fh->flags & FS_SOCKET) ) return -ESPIPE;

	switch(whence)
	{
		case SEEK_SET:
			fh->seek = off;
			break;
		case SEEK_CUR:
			fh->seek += off;
			break;
		case SEEK_END:
			fh->seek = fh->inode->st_size + off;
			break;
		default:
			return -EINVAL;
	}

	return fh->seek;
}

int do_close_socket(struct fileh *const fh, struct task *const this)
{
	if (!fh || !this)
		return -1;
	return 0;
}

struct fileh *do_dup(const struct fileh *const fh, struct task *const t)
{
	struct fileh *ret;

	if(fh->flags & FS_SOCKET) {
		printf("do_dup: attempt to dup a socket\n");
		return NULL;
	}

	ret = kmalloc(sizeof(struct fileh), "fileh.dup", t, 0);

	memcpy(ret, fh, sizeof(struct fileh));
	ret->task = t;
	ret->listen_next = NULL;

	return ret;
}

int do_close(struct fileh *const fh, struct task *const t)
{
	int rc = 0;

	if(fh->flags & FS_SOCKET) {
		rc = do_close_socket(fh, t);
	} else {
		rc = fh->fs->ops->close(t, fh);
		if(fh->fsent)
			free_fsent(fh->fsent);	

		if(fh->inode)
			close_inode(fh->inode);
	}
	kfree(fh);
	return rc;
}

struct fileh *do_open(const char *const name, struct task *const tsk, const int flags, const mode_t mode, int *const err)
{
	struct fileh *ret   = NULL;
	struct mount *mnt   = NULL;
	struct fsent *fsent = NULL;
	char *dir           = NULL;
	char *base          = NULL;
	void *priv          = NULL;
	ino_t rc            = 0;
	ino_t new_ino       = 0;
	bool create         = false;

	int tmp_error;
	int *error;

	error = err ? err : &tmp_error;
	*error = 0;

    /* try to find the file */
	//printf("do_open: trying to open '%s'\n", name);
	if((fsent = resolve_file(name, NULL, error)) == NULL) {
        /* we can't: if ENOENT and O_CREAT make one */
		//printf("do_open: unable to open\n");
		if(*error == -ENOENT && (flags & O_CREAT)) {
			//printf("do_open: will try to create\n");
			create = true;

            /* break apart from path */
			if((dir = dirname(name)) == NULL)
				goto fail;
			if((base = basename(name)) == NULL)
				goto fail;

            /* attempt to find the containing folder */
			//printf("do_open: find dir '%s'\n", dir);
			if((fsent = resolve_file(dir, NULL, error)) == NULL) {
				//printf("do_open: unable: %d: %s\n", *error, strerror(*error));
				goto fail;
			}
			/* FIXME
            if(fsent->child_fs)
                fsent = fsent->child_fs->root;
				*/
		} else {
            /* other error or not O_CREAT */
			//printf("do_open: wasn't O_CREAT or -ENOENT\n");
			goto fail;
		}
	}

	/* FIXME check that fsent is either a) the file or b) the folder for new */
	mnt = fsent->fs; 

	if((ret = kmalloc(sizeof(struct fileh), "fileh", tsk, KMF_ZERO)) == NULL) {
		*error = -ENOMEM;
		goto fail;
	}

	ret->fs     = mnt;
	ret->seek   = 0;
	ret->flags  = flags;
	ret->task   = tsk;
	ret->flags |= tsk ? 0 : FS_KERNEL;
	ret->fsent  = fsent;

	if(create) {
		//printf("do_open: creating a file in %s (%d,%d)\n", mnt->ops->name, DEV_MAJOR(mnt->dev->devid), DEV_MINOR(mnt->dev->devid));
		if((new_ino = rc = mnt->ops->create(tsk, mnt, ret, flags, mode, 0, &priv)) < 0) {
			//printf("do_open: file creation failed: %ld: %s\n", rc, strerror(rc));
			goto oops;
		}
		//printf("do_open: linking to file\n");
		if((rc = create_link(tsk, fsent, base, mnt, new_ino, &fsent)) < 0) {
			//printf("do_open: link failed: %ld: %s\n", rc, strerror(rc));
			goto oops;
		}
		/* be careful not to clobber else you'll try to open the superblock(0) */
		rc = new_ino;
		ret->fsent  = fsent;
	} else {
		rc = mnt->ops->open(tsk, mnt, fsent, ret, flags, mode, &priv);
		fsent->count++;
	}

	//printf("do_open: %s setting fsent to [%03ld](%d,%d)\n", name, fsent->ino, DEV_MAJOR(fsent->fs->dev->devid), DEV_MINOR(fsent->fs->dev->devid));

    /* we do not populate *error directly, as it is ino_t on success */
oops:
	if(rc < 0) {
		*error = rc;
		goto fail;
	}

    /* open the inode associated with this fsent */
	//printf("do_open: opening inode a file\n");
	if((ret->inode = open_inode(mnt, rc, error)) == NULL) {
		//printf("do_open: open failed: %d: %s\n", *error, strerror(*error));
		goto fail;
	}
	
	if(((ret->inode->flags & FS_CHAR) == FS_CHAR)) {
		if((ret->sdev.char_dev = find_dev(ret->inode->st_rdev, DEV_CHAR)) == NULL) {
			printf("do_open: char_dev not found for %x\n", ret->inode->st_rdev);
			goto fail;
		}
	} else if(((ret->inode->flags & FS_BLOCK) == FS_BLOCK)) {
		if((ret->sdev.blk_dev = find_dev(ret->inode->st_rdev, DEV_BLOCK)) == NULL) {
			printf("do_open: block_dev not found for %x\n", ret->inode->st_rdev);
			goto fail;
		}
	} 

    /* check we can actually access it */
	//printf("do_open: checking access\n");
	if((*error = access_check(ret, tsk, flags)) < 0) {
		//printf("do_open: access denied\n");
		goto fail;
	}

	if(!ret->inode->priv)
		ret->inode->priv = priv;

	fsent->inode = ret->inode;

fail:
	if(*error < 0 && ret) {
		do_close(ret, NULL);
		ret = NULL;
	}

	if(dir)
		kfree(dir);

	if(*error < 0 && fsent)
		fsent->count--;

	return ret;
}

ssize_t sys_read(const int fd, void *const data, const size_t len)
{
	const struct task *const t = &tasks[curtask];
	//printf("sys_read: fd=%x data=%p len=%lx\n", fd, (void *)data, len);

	if(len == 0) 
		return 0;
	else if(fd >= MAX_FD || fd < 0 || !t->fps[fd])
		return -EBADF;
	else if(data == NULL || !is_valid(data)) 
		return -EFAULT;

	return do_read(t->fps[fd], data, len);
}

ssize_t sys_write(const int fd, const void *const data, const size_t len)
{
	//printf("sys_write: fd=%x data=%p len=%lx\n", 
	//		fd, 
	//		(void *)data, 
	//		len);
	const struct task *const t = &tasks[curtask];

	if(len == 0) 
		return 0;
	else if(fd >= MAX_FD || fd < 0 || !t->fps[fd])
		return -EBADF;
	else if(data == NULL || !is_valid(data)) 
		return -EFAULT;

	return do_write(t->fps[fd], data, len);
}

int sys_close(const int fd)
{
	struct task *this = &tasks[curtask];

//	printf("sys_close[%x]: %x\n", curtask, fd);
	
	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) return -EBADF;

	long rc = do_close(this->fps[fd], this);
	this->fps[fd] = NULL;

	return rc;
}

int sys_socket(const int family, const int type, const int protocol)
{
	struct task *this = &tasks[curtask];
	int i,found;

	printf("sys_socket: %x, %x, %x\n", family, type, protocol);

	for(i=0,found=-1; i<MAX_FD; i++)
	{
		if(!this->fps[i]) {
			found = i;
			break;
		}
	}
	if(found == -1) goto fail;

	//this->fps[found] = do_socket(this, family, type, protocol);

	return found;

fail:
	return -1;
}

int sys_listen(const int fd, const int listen)
{
	struct task *const this = &tasks[curtask];

	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) 
		return -EBADF;
		
	return do_listen(this, this->fps[fd], listen);
}

int sys_accept(const int fd, struct sockaddr *const sa, socklen_t *const len)
{
	struct task *const this = &tasks[curtask];
	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) 
		return -EBADF;
	else if(!sa || !is_valid((uint8_t*)sa)) 
		return -EFAULT;
		
	return do_accept(this, this->fps[fd], sa, len);
}

int sys_bind(const int fd, struct sockaddr *const sa, const socklen_t len)
{
	struct task *const this = &tasks[curtask];

	//printf("sys_bind: %x, %x, %x\n", fd, sa, len);

	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) 
		return -EBADF;
	else if(!sa || !is_valid((uint8_t*)sa)) 
		return -EFAULT;
	else
		return do_bind(this, this->fps[fd], sa, len);
}

int sys_mkdir(const char *const pathname, mode_t mode)
{
	struct task *this = get_task(curtask);

	if(!pathname || !is_valid(pathname))
		return -EFAULT;

	return do_mkdir(this, pathname, mode);
}

int sys_open(const char *const name, const int flags, const mode_t mode)
{
	struct task *this;
	int ret;
	int i,found;

	this = &tasks[curtask];

	//printf("sys_open: name=%s flags=%x\n", name, flags);

	if(!name || !is_valid((uint8_t*)name))
		return -EFAULT;

	for(i=0,found=-1;i<MAX_FD;i++)
	{
		if(!this->fps[i]) {
			found = i;
			break;
		}
	}

	if( found == -1 )
		return -ENFILE;

	this->fps[found] = do_open(name, this, flags, mode, &ret);
	if( this->fps[found] == NULL )
		return ret;

	return found;
}

int sys_creat(const char *pathname, const mode_t mode)
{
	return sys_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

off_t sys_lseek(const int fd, const off_t offset, const int whence)
{
	const struct task *const this = &tasks[curtask];

	if(fd < 0 || fd > MAX_FD || this->fps[fd] == NULL)
		return -EBADF;

	return do_lseek(this->fps[fd], offset, whence);
}
