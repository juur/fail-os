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
static int inodes_lock = 0;

static struct fsent *fsents;
static int fsents_lock;

__attribute__((nonnull))
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
static void dump_fsent(const struct fsent *const start, const bool children)
{
	struct fsent *tmp;
	const struct fsent *i = start;

	printf("fsent: [%03ld]{%d,%d}'%10s' lck:%2d ", 
			//(void *)i,
			i->self_ino,
			DEV_MAJOR(i->fs->dev->devid),
			DEV_MINOR(i->fs->dev->devid),
            i->name,
			i->count
			);
	if(i->parent && i->parent != i)
		printf(" (parent: [%03ld]{%d,%d}'%10s')",
				i->parent->self_ino,
				DEV_MAJOR(i->parent->fs->dev->devid),
				DEV_MINOR(i->parent->fs->dev->devid),
                i->parent->name
			  );
	if(i->sibling)
		printf(" (sibling: [%03ld]{%d,%d}'%10s')",
                i->sibling->self_ino,
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
    //printf(BYEL "add_fsent: name=<%s> ino=%d"CRESET"\n", i->name, i->self_ino);
	spin_lock(&fsents_lock); {
        for (const struct fsent *tmp = fsents; tmp; tmp = tmp->next)
            if (i == tmp)
                goto done;
		i->next = fsents;
		fsents  = i;
	}
done:
    spin_unlock(&fsents_lock);
}

__attribute__((nonnull,unused))
static void remove_fsent(struct fsent *const f)
{
    //printf(BYEL "remove_fsent: name=<%s> ino=%d"CRESET"\n", f->name, f->self_ino);
	spin_lock(&fsents_lock); {
		for(struct fsent *tmp = fsents; tmp; tmp = tmp->next)
			if(tmp->next == f) {
				tmp->next = f->next;
				break;
			}
		if(fsents == f)
			fsents = f->next;
	} spin_unlock(&fsents_lock);
}

__attribute__((nonnull,unused))
static void remove_inode(struct inode *const i)
{
	spin_lock(&inodes_lock); {
		for(struct inode *tmp = inodes; tmp; tmp = tmp->next)
			if(tmp->next == i) {
				tmp->next = i->next;
				break;
			}
		if(inodes == i)
			inodes = i->next;
	} spin_unlock(&inodes_lock);
}

__attribute__((nonnull))
static void close_inode(struct inode *const i)
{
	//printf("close_inode: %p\n", (void*)i);

	spin_lock(&i->lock); {
		i->count--;
	} spin_unlock(&i->lock);
}

__attribute__((nonnull)) 
static long close_fsent(struct fsent *const fsent)
{
    if (fsent->flags & FS_DELETED) {
		printf("free_fsent: double delete [%03ld] count:%d\n", fsent->self_ino, fsent->count);
        return -EINVAL;
	}

	spin_lock(&fsent->lock); {
		fsent->count--;
	} spin_unlock(&fsent->lock);

	return 0;
}

__attribute__((nonnull))
static void delete_one(struct fsent *ent)
{
    printf("delete_one: name=<%s> ino=%lu\n", ent->name, ent->self_ino);

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

__attribute__((nonnull(1,4)))
struct fsent *create_fsent(struct mount *mnt, struct fsent *parent, ino_t ino, 
        long *error, const char *new_name, const bool is_new)
{
	struct fsent *ret = NULL;
	*error = 0;

	//printf("create_fsent: ino=%lu,new_name=%s,is_new=%d\n", ino, new_name, is_new);

    if (ino == (ino_t)-1) {
		//printf("create_fsent: ino is -1LL\n");
        *error = -EINVAL;
        return NULL;
    }

	if ((ret = kmalloc(sizeof(struct fsent), "fsent", NULL, KMF_ZERO)) == NULL) {
		*error = -ENOMEM;
		goto fail;
	}

	ret->parent   = parent;
	ret->fs       = mnt;
	ret->self_ino = ino;
	ret->count    = 1;

	if (is_new) {
		if(new_name == NULL) {
			//printf("create_fsent: new_name is NULL\n");
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
	if(is_new && parent && (*error = parent->fs->ops->sync_fsent(parent, SYNC_WRITE)) < 0) {
		//printf("create_fsent: failed to sync parent: %d: %s\n", *error, strerror(*error));
		goto fail;
	}

	if((*error = mnt->ops->sync_fsent(ret, is_new ? SYNC_WRITE : SYNC_READ)) < 0) {
		//printf("create_fsent: failed to sync: %d: %s\n", *error, strerror(*error));
		goto fail;
	}

	/*
	printf("create_fsent: @%p [%ld(%d,%d){%s}]: parent=%ld(%d:%d){%s} parent->child=%ld(%d:%d){%s} sibling=%ld(%d:%d){%s}\n",
			(void *)ret,
			ino, 
			DEV_MAJOR(mnt->dev->devid), 
			DEV_MINOR(mnt->dev->devid),
			ret->name,
			parent ? parent->self_ino : -1, 
			parent ? DEV_MAJOR(parent->fs->dev->devid) : -1, 
			parent ? DEV_MINOR(parent->fs->dev->devid) : -1,
			parent ? parent->name : "",
			parent && parent->child ? parent->child->self_ino : -1, 
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
		close_fsent(ret);

	return NULL;
}

__attribute__((nonnull))
struct inode *open_inode(struct mount *const m, const ino_t inode, long *error)
{
	struct inode *ret = NULL;
	if (inode <= 0)
		return NULL;

    /*
	printf("open_inode: m=%p m->dev=%p inode=%lx dev=(%d,%d)\n", 
			(void *)m,
			(void *)m->dev,
			inode, 
			DEV_MAJOR(m->dev->devid),
			DEV_MINOR(m->dev->devid)
		  );
          */

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

        if(ret) {
            spin_unlock(&inodes_lock);
            goto success;
        }

        if((ret = kmalloc(sizeof(struct inode), "inode", NULL, KMF_ZERO)) == NULL) {
            *error = -ENOMEM;
            goto fail;
        }

        ret->count++;
        ret->mnt = m;
        if(m->ops->sync_inode(ret, inode, SYNC_READ) < 0)
            goto fail;

    } spin_unlock(&inodes_lock);
    add_inode(ret);

success:
    return ret;

fail:
    spin_unlock(&inodes_lock);
    if(ret)
        kfree(ret);
    return NULL;
}

    __attribute__((nonnull(1)))
static long access_check(struct fileh *const fh, struct task *const tsk, const int flags)
{
    if(!tsk)
        return 0; /* kernel always succeeds */

    if(fh->flags & FS_KERNEL) {
        printf("access_check: is kernel\n");
        return -EPERM;
	}

    if(tsk->euid == 0)
        return 0; /* root always succeeds   */

    bool ret = -EPERM;

	
    const uid_t  u = tsk->euid;
    const gid_t  g = tsk->egid;
    const uid_t fu = fh->inode->st_uid;
    const gid_t fg = fh->inode->st_gid;
    const mode_t m = fh->inode->st_mode;
	
	//printf("access_check: euid=%d egid=%d st_uid=%d st_gid=%d\n", u, g, fu, fg);

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
	long dummy_error;

	//printf("find_or_create: on=(%d,%d) ino=%ld\n", 
	//		DEV_MAJOR(mnt->dev->devid),
	//		DEV_MINOR(mnt->dev->devid),
	//		ino);

	if (ino == (ino_t)-1)
		return NULL;

	spin_lock(&fsents_lock); {
		for (tmp = fsents; tmp; tmp = tmp->next)
		{
			if (tmp->self_ino == ino && tmp->fs == mnt ) {
				//printf("find_or_create: found: %s\n", tmp->name);
				ret = tmp;
				break;
			}
		}
	} spin_unlock(&fsents_lock);
	if (ret)
		goto done;

	ret = create_fsent(mnt, cwd, ino, &dummy_error, NULL, false);
	//printf("find_or_create: created: %s[%ld]{s:%ld}\n", ret ? ret->name : "FAILED", ino, ret ? ret->sibling_ino : 0);

done:
	return ret;
}

/**
 * populates the child node of an fsent
 */
__attribute__((nonnull))
static bool populate_dir(struct fsent *const cwd)
{
    //printf("populate_dir\n");
	//printf(BGRN "populate_dir: cwd.child_ino=%ld cwd.name=%s"CRESET"\n", cwd->child_ino, cwd->name);

	/* check we haven't already checked it */
	if (cwd->child_ino == -1UL || !cwd->child_ino || cwd->child) {
		//printf(BGRN "populate_dir: child fail\n" CRESET);
		return cwd->child != NULL;
	}

	/*
	struct mount *where = child_fs ? cwd->child_fs : cwd->fs;
	struct fsent *root  = cwd->child_fs ? where->root   : cwd;
	*/
	
	struct mount *where = cwd->fs;
	struct fsent *root  = cwd;

	//printf("populate_dir: create root->child\n");
	if ((root->child = find_or_create(where, root, cwd->child_ino)) == NULL) {
		printf("populate_dir: is not a directory (no children)\n");
		return false;
	}

	struct fsent *tmp_fsent = root->child;
	ino_t sibling_ino = tmp_fsent->sibling_ino;

	/*
	if(tmp && tmpi>0)
		printf("populate_dir: creating siblings\n");
	else
		printf("populate_dir: no siblings '%p' %ld\n", (void *)tmp, tmpi);
	*/

    bool found_one = false;

	/* iterate whilst we have an active inode with a sibling */
	while (tmp_fsent && sibling_ino > 0)
	{
		if ((tmp_fsent->sibling = find_or_create(where, root, sibling_ino)) != NULL) {
            found_one = true;
			//printf("populate_dir: %s: added %s ino:%lu at %p\n", 
			//		tmp_fsent->name, tmp_fsent->sibling->name, sibling_ino, (void *)tmp_fsent->sibling);
		}
		tmp_fsent = tmp_fsent->sibling;
		if (tmp_fsent)
			sibling_ino = tmp_fsent->sibling_ino;
		else
			sibling_ino = -1;
		//printf("populate_dir: next checking tmp=%p[%s] sibling tmpi=%lu\n", (void *)tmp, tmp ? tmp->name : "", tmpi);
	}
	//printf("populate_dir: done\n");
	if (tmp_fsent)
		tmp_fsent->sibling = NULL; // FIXME

    return found_one;
}

__attribute__((nonnull))
static struct fsent *find_fsent(struct fsent *const cwd, const char *const name, long *error)
{
	struct fsent *ret = NULL;
	*error            = 0;

    /*
	printf(BRED "find_fsent: cwd=%s(%d,%d) name=%s"CRESET"\n", 
            cwd->name,
            DEV_MAJOR(cwd->fs->dev->devid),
            DEV_MINOR(cwd->fs->dev->devid),
            name);
    */

    //dump_fsent(cwd, false);

    if(!cwd->child) {
        //printf(BRED "find_fsent: need to populate child"CRESET"\n");
        populate_dir(cwd);
    } else {
        //printf(BRED "find_fsent: has children: %s"CRESET"\n", cwd->child->name);
    }

    //printf("find_fsent: child OK\n");

	for(ret = cwd->child; ret; ret = ret->sibling) {
		//printf("find_fsent: checking ino=%ld [%s][%d]", ret->self_ino, ret->name, ret->flags & FS_DELETED);
		//printf(" '%s'=='%s' %d\n", name, ret->name, !strcmp(name, ret->name));

		if(!(ret->flags & FS_DELETED) && !strcmp(name, ret->name)) {
			//printf(BRED "find_fsent: found: ino=%ld for name=%s cwd=%s"CRESET"\n", ret->self_ino, ret->name, cwd->name);
            if (!ret->child && ret->child_ino != -1UL)
                populate_dir(ret);
			return ret;
		}
	}
	//printf("find_fsent: failed\n");

	return NULL;
}

/* TODO add a cwd */
__attribute__((nonnull(1)))
struct fsent *resolve_file(const char *const name, struct fsent *const cwd, long *error)
{
	struct fsent *cur, *tmpi;
	char *oldpart, *part, *saveptr, *fn;

	*error = -ENOENT;

	//printf("resolve_file: %s in %s\n", name, cwd ? cwd->name : "ROOT");

	cur = cwd ? cwd : root_fsent;

	//printf("resolve_file: about to strdup(0x%p)\n", name);
	if((fn = strdup(name)) == NULL) {
		*error = -ENOMEM;
		goto fail;
	}


	oldpart = fn;
	//printf("resolve_file: about to strtok_r\n");
	part = strtok_r(fn, "/", &saveptr);

	bool running = true;

	while(running && cur && part)
	{
		//printf("resolve_file: cur=%s part:%s oldpart:%s\n", cur->name, part, oldpart);

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

		//printf(BCYN"resolve_file: find_fsent(%s, %s)"CRESET"\n", cur->name, part);
		if ((tmpi = find_fsent(cur, part, error)) == NULL && *error)
			goto fail;
		else if (tmpi != NULL)
			cur = tmpi;
		else {
			*error = -ENOENT;
			goto fail;
		}
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
static long create_link(struct task *tsk, struct fsent *cwd, const char *name, struct mount *mnt, ino_t dest, struct fsent **ret)
{
	struct fsent *new_name = NULL;
	long error = 0;

	//printf("create_link: cwd=%s, name=%s, dest=%lu\n", cwd->name, name, dest);

	if((new_name = create_fsent(mnt, cwd, dest, &error, name, true)) == NULL) {
		//printf("create_link: create_fsent failed %d:%s\n", error, strerror(error));
		goto fail;
	}

	if((error = mnt->ops->link(tsk, new_name, dest)) < 0) {
		//printf("create_link: ops[%s]->link failed %d:%s\n", mnt->ops->name, error, strerror(error));
		goto fail;
	}

	*ret = new_name;

	//printf("create_link: done\n");

	return 0;
fail:
	if(new_name)
		close_fsent(new_name);

	return error;
}

__attribute__((nonnull(1,3)))
struct mount *do_mount(struct block_dev *const dev, struct fsent *from_point, const struct fs_ops *const fsops)
{
	struct mount *mnt;
	int error;
	ino_t root_inode;
	struct fsent *point = from_point;
	
	if((mnt = kmalloc(sizeof(struct mount), "mount", NULL, KMF_ZERO)) == NULL)
		return NULL;

	/*
	printf("do_mount: [%x:%x] on '%s' type '%s'\n", 
            DEV_MAJOR(dev->devid), 
            DEV_MINOR(dev->devid),
            point ? point->name : "(null)", 
            &fsops->name[0]);
			*/

	mnt->dev   = dev;
	mnt->ops   = fsops;
	mnt->super = NULL;
	mnt->point = point;

	if(IS_ERR(root_inode = fsops->mount(mnt))) {
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
		//dump_fsent(point, false);

		point->count++;
		
		/* is there a better way to replace the mount point ? 
		 * should we unlink from the list the point and replace with mnt->root ?
		 *
		 * FIXME this is probably a pile of crap
		 */

		struct fsent *start;

		if (point->parent->child == point) {
			point->parent->child = mnt->root;
		} else for (start = point->parent->child; start; start = start->sibling)
		{
			if (start->sibling == point) {
				start->sibling = mnt->root;
				break;
			}
		}
		strcpy((char *)mnt->root->name, point->name);
		point = mnt->root;

	}

	spin_lock(&mounts_lock); {
        mnt->next = mounts;
        mounts    = mnt;
	}; spin_unlock(&mounts_lock);

	

	/*
	printf("do_mount: [%x:%x] mounted on '%s' with fstype '%s'\n", 
            DEV_MAJOR(dev->devid), 
            DEV_MINOR(dev->devid),
            point ? point->name : "(null)", 
            &fsops->name[0]);

	if (point)
		dump_fsent(point, false);
		*/

	return mnt;

fail:
	if(mnt && root_inode) fsops->umount(mnt);
	if(mnt) kfree(mnt);
	return NULL;
}

__attribute__((nonnull))
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

long do_ioctl(struct fileh *const fh, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOTTY;

	if ((fh->inode->flags & FS_CHAR) == FS_CHAR) {
		ret = fh->sdev.char_dev->ops->ioctl(fh->sdev.char_dev, fh->task, cmd, arg);
	} else if ((fh->inode->flags & FS_BLOCK) == FS_BLOCK) {
	} else if (fh->flags & FS_SOCKET) {
	} else {
	}

	return ret;
}

long sys_ioctl(int fd, unsigned long cmd, unsigned long arg)
{
	const struct task *const this = get_current_task();

	if (fd < 0 || fd > MAX_FD || this->fps[fd] == NULL)
		return -EBADF;

	//printf("sys_ioctl: %x, %lx, %lx\n", fd, cmd, arg);
	return do_ioctl(this->fps[fd], cmd, arg);
}

__attribute__((nonnull))
ssize_t do_read(struct fileh *const fh, char *const dst, const size_t len)
{
	ssize_t ret = 0;

	//printf("do_read: fh=%p %lx - %lx [%lx]\n", (void *)fh, (uintptr_t)dst, (uintptr_t)dst+len, len);

	if (fh->inode == NULL) {
		//printf("do_read: fh->inode is NULL!");
		return -EINVAL;
	} if((fh->inode->flags & FS_CHAR) == FS_CHAR) {
		//printf("do_read: special char\n");
		if(fh->sdev.char_dev && fh->sdev.char_dev->ops && fh->sdev.char_dev->ops->read) {
			//printf("do_read: char_dev: %s\n", 
			//		fh->sdev.char_dev->ops->name
			//		);
			ret = fh->sdev.char_dev->ops->read(fh->sdev.char_dev, dst, len);
		} else {
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
		//printf("do_read socket\n");
		ret = 0;
	} else {
		//printf("do_read: file\n");
		if((ret = fh->fs->ops->read(fh, dst, len, fh->seek)) > 0)
			fh->seek += ret;
	}
	//printf("do_read: read %lx\n", ret);
	return ret;
}

__attribute__((nonnull(2)))
long do_mkdir(struct task *const tsk, const char *pathname, const mode_t mode)
{
	struct fsent *fsent     = NULL;
	struct fsent *new_fsent = NULL;
	long error               = -EEXIST;
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
        close_fsent(new_fsent);

	return error;
}

__attribute__((nonnull))
off_t do_lseek(struct fileh *fh, off_t off, int whence)
{
	if( (fh->flags & FS_SOCKET) ) return -ESPIPE;
    if( S_ISDIR(fh->fsent->flags) ) return -EINVAL;
    if( S_ISFIFO(fh->fsent->flags) ) return -ESPIPE;
    if( S_ISSOCK(fh->fsent->flags) ) return -ESPIPE;

    off_t new_off = -1;

	switch(whence)
	{
		case SEEK_SET:
			new_off = off;
			break;
		case SEEK_CUR:
			new_off = fh->seek + off;
			break;
		case SEEK_END:
			new_off = fh->seek + fh->inode->st_size + off;
			break;
		default:
			return -EINVAL;
	}

    if (new_off < 0 || new_off >= (fh->inode->st_size))
        return -EINVAL;

	return (fh->seek = new_off);
}

long do_close_socket(struct fileh *const fh, struct task *const this)
{
	if (!fh || !this)
		return -EBADF;
	return 0;
}

struct fileh *do_dup(const struct fileh *fh, struct task *t, long *error)
{
	struct fileh *ret = NULL;

	if(fh->flags & FS_SOCKET) {
		printf("do_dup: attempt to dup a socket\n");
		*error = -EBADF;
        goto fail;
	}

	ret = kmalloc(sizeof(struct fileh), "fileh.dup", t, 0);
	if (!ret) {
		*error = -ENOMEM;
        goto fail;
	}

	memcpy(ret, fh, sizeof(struct fileh));
	ret->task = t;

    if (ret->fsent) {
        spin_lock(&ret->fsent->lock); {
            ret->fsent->count++;
        } spin_unlock(&ret->fsent->lock);
    }
    if (ret->inode) {
        spin_lock(&ret->inode->lock); {
            ret->inode->count++;
        } spin_unlock(&ret->inode->lock);
    }

	ret->listen_next = NULL;

fail:
	return ret;
}

__attribute__((nonnull(1)))
long do_close(struct fileh *fh, struct task *t)
{
	int rc = 0;

    if (t) {
        for(int i = 0; i < MAX_FD; i++)
            if (t->fps[i] == fh)
                t->fps[i] = NULL;
    }   

	if(fh->flags & FS_SOCKET) {
		rc = do_close_socket(fh, t);
	} else {
		rc = fh->fs->ops->close(t, fh);
        fh->fs = NULL;

		if(fh->fsent) {
			//printf("do_close: fsent\n");
			close_fsent(fh->fsent);	
            fh->fsent = NULL;
		}

		if(fh->inode) {
			//printf("do_close: inode\n");
			close_inode(fh->inode);
            fh->inode = NULL;
		}
	}
	//printf("do_close: free\n");
	kfree(fh);
	return rc;
}

ssize_t do_getdents64(struct task *task, struct fileh *dir, struct dirent64 *ent, size_t count)
{
	if ( (dir->flags & FS_DIR) != FS_DIR )
		return -ENOTDIR;

	size_t ret = 0;
	size_t remaining = count;
	size_t len;
	size_t entries = 0;
	struct dirent64 *c_ent = ent;
	struct fsent *c_file = dir->fsent;

	//printf("do_getdents64: count=%lx seek=%lx\n", count, dir->seek);

	while(c_file) {
		if (entries < dir->seek) {
			entries++;
			goto skip;
		}

		len = sizeof(struct dirent64);

		switch (entries) {
			case 0:
				len += 2; /* "."  */
				break;
			case 1:
				len += 3; /* ".." */
				break;
			default:
				len += strlen(c_file->name) + 1;
				break;
		}

		if (len > remaining)
			return -EINVAL;

		c_ent->d_ino    = c_file->self_ino;
		c_ent->d_off    = entries;
		c_ent->d_reclen = len;
		c_ent->d_type   = 0; /* TODO */

		switch (entries) {
			case 0:
				strcpy(c_ent->d_name, ".");
				break;
			case 1:
				strcpy(c_ent->d_name, "..");
				break;
			default:
				strcpy(c_ent->d_name, c_file->name);
				break;
		}

		remaining -= len;
		ret       += len;


		//printf("do_getdents64[%2lx]: > %10s [flags=%2x len=%2lx]\n", 
		//		entries, c_ent->d_name, c_file->flags, len);

		c_ent = (struct dirent64 *)( ((uintptr_t)c_ent) + len );

		dir->seek++;
		entries++;
		

		/* replace with entries==1 . entries==2 .. then so on */
skip:
		/* note entries++ has happened */
		if (entries == 1)
			c_file = dir->fsent->parent ? dir->fsent->parent : dir->fsent;
		else if (entries == 2)
			c_file = dir->fsent->child;
		else
			c_file = c_file->sibling;
	}

	return ret;
}

ssize_t sys_getdents64(int fd, void *dirp, size_t count)
{
	struct task *this;

	if (!dirp || !is_valid(dirp))
		return -EFAULT;

	this = get_current_task();

	if (fd < 0 || fd >= MAX_FD || !this->fps[fd])
		return -EBADF;

	return do_getdents64(this, this->fps[fd], (struct dirent64 *)dirp, count);
}

struct fileh *do_open(const char *name, struct task *tsk, int flags, mode_t mode, long *err, dev_t dev)
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

	long tmp_error;
	long *error;

	error = err ? err : &tmp_error;
	*error = 0;
	
	//printf("do_open: trying to open '%s' with mode=%x flags=%x dev=%x\n", name, mode, flags, dev);

    /* try to find the file */
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
				//printf("do_open: unable: %ld: %s\n", *error, strerror(*error));
				goto fail;
			}
			/* FIXME
            if(fsent->child_fs)
                fsent = fsent->child_fs->root;
				*/
		} else {
            /* other error or not O_CREAT */
			//printf("do_open: wasn't O_CREAT or -ENOENT\n");
            ret = NULL;
			goto fail;
		}
	} else {
		//printf("do_open: resolve_file=%s\n", fsent->name);
	}

	/* FIXME check that fsent is either a) the file or b) the folder for new */
	mnt = fsent->fs; 

	if((ret = kmalloc(sizeof(struct fileh), "fileh", tsk, KMF_ZERO)) == NULL) {
		*error = -ENOMEM;
        ret = NULL;
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
		if(IS_ERR(new_ino = rc = mnt->ops->create(tsk, mnt, ret, flags, mode, dev, &priv))) {
			//printf("do_open: file creation failed: %ld: %s\n", rc, strerror(rc));
			goto oops;
		}
		//printf("do_open: linking to file new_ino=%lu\n", new_ino);
		if(IS_ERR(rc = create_link(tsk, fsent, base, mnt, new_ino, &fsent))) {
			//printf("do_open: link failed: %ld: %s\n", rc, strerror(rc));
			goto oops;
		}
		/* be careful not to clobber else you'll try to open the superblock(0) */
		rc = new_ino;
		ret->fsent  = fsent; /* TODO replace fsent (parent) with child? */
	} else {
		//printf("do_open: invoking FS open: fs=%s\n", mnt->ops->name);
		rc = mnt->ops->open(tsk, mnt, fsent, ret, flags, mode, &priv);
		//printf("do_open: done: %lu\n", rc);
		fsent->count++;
	}

	//printf("do_open: %s setting fsent to [%03ld](%d,%d)\n", name, fsent->self_ino, DEV_MAJOR(fsent->fs->dev->devid), DEV_MINOR(fsent->fs->dev->devid));

    /* we do not populate *error directly, as it is ino_t on success */
oops:
	if(IS_ERR(rc)) {
		//printf("do_open: an error occured: %ld: %s\n", (long)rc, strerror(rc));
        ret = NULL;
		*error = rc;
		goto fail;
	}

    /* open the inode associated with this fsent */
	//printf("do_open: opening inode a file: rc=%lu\n", rc);
	if((ret->inode = open_inode(mnt, rc, error)) == NULL) {
		//printf("do_open: open_inode failed: %d: %s\n", *error, strerror(*error));
        ret = NULL;
		goto fail;
	}

	//printf("do_open: flags=%08lx flags[%x] & O_DIRECTORY[%x]=%x inode->flags & FS_DIR=%lx\n",
	//		ret->inode->flags,
	//		flags,
	//		O_DIRECTORY,
	//		flags & O_DIRECTORY,
	//		ret->inode->flags & FS_DIR
	//		);
	if ( (flags & O_DIRECTORY) && ((ret->inode->flags & FS_DIR) != FS_DIR) ) {
		//printf("do_open: requested O_DIRECTORY but file is not\n");
        ret = NULL;
		*error = -ENOTDIR;
		goto fail;
	}
	
	if(((ret->inode->flags & FS_CHAR) == FS_CHAR)) {
		if((ret->sdev.char_dev = find_dev(ret->inode->st_rdev, DEV_CHAR)) == NULL) {
			printf("do_open: char_dev not found for %x\n", ret->inode->st_rdev);
            ret = NULL;
			goto fail;
		}
	} else if(((ret->inode->flags & FS_BLOCK) == FS_BLOCK)) {
		if((ret->sdev.blk_dev = find_dev(ret->inode->st_rdev, DEV_BLOCK)) == NULL) {
			printf("do_open: block_dev not found for %x\n", ret->inode->st_rdev);
            ret = NULL;
			goto fail;
		}
	} 

    /* check we can actually access it */
	//printf("do_open: checking access\n");
	if((*error = access_check(ret, tsk, flags)) < 0) {
		printf("do_open: access denied\n");
        ret = NULL;
		goto fail;
	}

	if(!ret->inode->priv)
		ret->inode->priv = priv;

	fsent->inode = ret->inode;

	//printf("do_open: %p inode set to %p type=%u\n", 
	//		(void *)ret, (void *)ret->inode, ret->type);

fail:
    //printf("do_open: failed\n");
	if (*error < 0 && fsent && !ret)
		fsent->count--;
	else if (*error < 0 && ret) {
		do_close(ret, NULL);
		ret = NULL;
	}

	if (dir)
		kfree(dir);

	if (base)
		kfree(base);

	return ret;
}

ssize_t sys_read(const int fd, void *const data, const size_t len)
{
	const struct task *const t = get_current_task();
	//printf("sys_read: fd=%x data=%p len=%lx\n", fd, (void *)data, len);

	if(len == 0) 
		return 0;
	else if(fd >= MAX_FD || fd < 0 || !t->fps[fd])
		return -EBADF;
	else if(data == NULL || !is_valid(data)) 
		return -EFAULT;

	long rc = do_read(t->fps[fd], data, len);
	//printf("sys_read: returning %ld rc\n", rc);
	return rc;
}

ssize_t sys_write(const int fd, const void *const data, const size_t len)
{
	//printf("sys_write: fd=%x data=%p len=%lx\n", fd, (void *)data, len);
	const struct task *const t = get_current_task();

	if(len == 0) 
		return 0;
	else if(fd >= MAX_FD || fd < 0 || !t->fps[fd])
		return -EBADF;
	else if(data == NULL || !is_valid(data)) 
		return -EFAULT;

	return do_write(t->fps[fd], data, len);
}

long sys_close(const int fd)
{
	struct task *ctsk = get_current_task();

	//printf("sys_close: %x\n", fd);
	
	if(fd < 0 || fd >= MAX_FD || !ctsk->fps[fd]) {
		printf("sys_close: -EBADF\n");
		return -EBADF;
	}

	long rc = do_close(ctsk->fps[fd], ctsk);
	ctsk->fps[fd] = NULL;

	return rc;
}

long sys_socket(const int family, const int type, const int protocol)
{

	//printf("sys_socket: %x, %x, %x\n", family, type, protocol);
#ifdef WANT_NET
	struct task *this = get_current_task();
	int i, found;
	long ret = -ENFILE;

	for(i=0,found=-1; i<MAX_FD; i++)
	{
		if(!this->fps[i]) {
			found = i;
			break;
		}
	}
	if (found == -1) 
		goto fail;

	if ((this->fps[found] = do_socket(this, family, type, protocol, &ret)) == NULL)
		goto fail;

	//printf("sys_socket: new fd %d\n", found);
	return found;

fail:
#endif
	printf("sys_socket: %ld\n", ret);
	return ret;
}

long sys_listen(const int fd, const int listen)
{
	struct task *const this = get_current_task();

	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) 
		return -EBADF;
#ifdef WANT_NET	
	return do_listen(this, this->fps[fd], listen);
#else
	return -ENOSYS;
#endif
}

long sys_accept(const int fd, struct sockaddr *const sa, socklen_t *const len)
{
	struct task *const this = get_current_task();
	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) 
		return -EBADF;
	else if(!sa || !is_valid((uint8_t*)sa)) 
		return -EFAULT;
#ifdef WANT_NET		
	return do_accept(this, this->fps[fd], sa, len);
#else
	return -ENOSYS;
#endif
}

long sys_bind(const int fd, struct sockaddr *const sa, const socklen_t len)
{
	struct task *const this = get_current_task();

	//printf("sys_bind: %x, %x, %x\n", fd, sa, len);

	if(fd < 0 || fd >= MAX_FD || !this->fps[fd]) 
		return -EBADF;
	else if(!sa || !is_valid((uint8_t*)sa)) 
		return -EFAULT;
	else
#ifdef WANT_NET
		return do_bind(this, this->fps[fd], sa, len);
#else
	return -ENOSYS;
#endif
}

long sys_mkdir(const char *const pathname, mode_t mode)
{
	struct task *this = get_current_task();

	if(!pathname || !is_valid(pathname))
		return -EFAULT;

	return do_mkdir(this, pathname, mode);
}

long sys_access(const char *const pathname, const int mode)
{
	struct fileh *fh;
	struct task *this;
	long ret = 0;

	this = get_current_task();

	//printf("sys_access: name=%s mode=%d\n", pathname, mode);

	if ((fh = do_open(pathname, this, O_RDONLY, 0, &ret, 0)) == NULL)
		return -ENOENT;

	/* TODO invoke access_check() */

	//printf("sys_access: do_open is OK\n");

	do_close(fh, this);
	return ret;
}

long sys_open(const char *const name, const int flags, const mode_t mode)
{
	struct task *this;
	long ret;
	int i,found;

	this = get_current_task();

	//dump_pools();

	//printf("sys_open: name=%s flags=%x\n", name, flags);

	if(!name || !is_valid((uint8_t*)name))
		return -EFAULT;

	for(i=0,found=-1; i<MAX_FD; i++)
	{
		if(this->fps[i] == NULL) {
			found = i;
			break;
		}
	}

	if( found == -1 ) {
		//printf("sys_open: not found\n");
		/*for (i=0; i<MAX_FD;i++)
			printf("fps[%d]=%p\n", i, (void *)this->fps[i]);*/
		return -ENFILE;
	}

	this->fps[found] = do_open(name, this, flags, mode, &ret, 0);
	if( this->fps[found] == NULL ) {
		//printf("sys_open: returning %ld\n", ret);
		return ret;
	}

	//printf("sys_open: new fd on %d\n", found);
	return found;
}

long do_fstat(struct task *t, struct fileh *f, struct stat *statbuf)
{
	if (!statbuf)
		return -EINVAL;

	if (!f->inode)
		return -EINVAL;

	statbuf->st_uid     = f->inode->st_uid;
	statbuf->st_gid     = f->inode->st_gid;
	statbuf->st_dev     = f->inode->st_dev;
	statbuf->st_blksize = f->inode->st_blksize;
	statbuf->st_blocks  = f->inode->st_blocks;
	statbuf->st_size    = f->inode->st_size;
	statbuf->st_mode    = f->inode->st_mode;
	statbuf->st_ino     = f->inode->st_ino;

	//printf("fstat: st_mode=%x\n", statbuf->st_mode);

	return 0;
}

long do_stat(struct task *t, const char *pathname, struct stat *statbuf)
{
	long rc = 0;

	struct fileh *file = do_open(pathname, t, O_RDONLY, 0, &rc, 0);

	if (file == NULL)
		return rc;

	return do_fstat(t, file, statbuf);
}

long sys_creat(const char *pathname, const mode_t mode)
{
	return sys_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

off_t sys_lseek(const int fd, off_t offset, int whence)
{
	const struct task *this = get_current_task();
    struct fileh *fh;

	//printf("sys_lseek: offset=%ld whence=%d\n", offset, whence);

    if ((fh = get_proc_fh(this, fd)) == NULL)
		return -EBADF;

	return do_lseek(fh, offset, whence);
}

long sys_fstat(int fd, struct stat *statbuf)
{
	//printf("sys_fstat\n");
	struct task *ctsk = get_current_task();
	//dump_pools();

    if (get_proc_fh(ctsk, fd) == NULL)
		return -EBADF;

	return do_fstat(ctsk, ctsk->fps[fd], statbuf);
}

long sys_stat(const char *pathname, struct stat *statbuf)
{
	long ret;
	struct task *ctsk = get_current_task();
	//printf("sys_stat: %s\n", pathname);
	//dump_pools();

	ret = do_stat(ctsk, pathname, statbuf);
	//printf("sys_stat: returning %ld: %s\n", ret, strerror(-ret));

	return ret;
}

long sys_connect(int sockfs, const struct sockaddr *addr, socklen_t addrlen)
{
	return -ECONNREFUSED;
}

long sys_mount(const char *src, const char *tgt, const char *fstype, unsigned long flags, const void *data)
{
	return -ENODEV;
}

struct fileh *get_proc_fh(const struct task *task, int fd)
{
    if (fd < 0)
        return NULL;
    if (fd >= MAX_FD)
        return NULL;
    return task->fps[fd];
}

long sys_dup(int oldfd)
{
	struct task *ctsk = get_current_task();
    struct fileh *old_fh;
	long rc = -EMFILE;

    if ( (old_fh = get_proc_fh(ctsk, oldfd)) == NULL)
		return -EBADF;

	for (int i = 0; i < MAX_FD; i++)
		if (ctsk->fps[i] == NULL) {
			rc = i;
			ctsk->fps[i] = do_dup(old_fh, ctsk, &rc);
			break;
		}

	return rc;
}

char *do_getcwd(struct task *task, char *buf, size_t size)
{
    strncpy(buf, "/", size);
    return buf;
}

char *sys_getcwd(char *buf, size_t size)
{
    if (!size || !buf || !is_valid(buf))
        return (char *)-EINVAL;

    printf("sys_getcwd: %08lx[%lx]\n", (uintptr_t)buf, size);
    return do_getcwd(get_current_task(), buf, size);
}

long do_chdir(struct task *ctsk, const char *path)
{
	/* FIXME TODO */
	return 0;
}

long sys_chdir(const char *path)
{
	return do_chdir(get_current_task(), path);
}

long sys_mknod(const char *pathname, mode_t mode, dev_t dev)
{
	struct fileh *ret;
	struct task *ctsk = get_current_task();
	long rc;

	//printf("sys_mknod\n");

	if ((ret = do_open(pathname, ctsk, O_CREAT, mode, &rc, dev)) == NULL) {
		printf("sys_mknod: fail with %ld\n", rc);
		return rc;
	}

	do_close(ret, ctsk);
	//printf("sys_mknod: succeed\n");
	return 0;
}
