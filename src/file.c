#include "file.h"
#include "mem.h"
#include "block.h"
#include "dev.h"
#include "proc.h"
#include "net.h"

struct mount *mounts,*root;

void print_fh(struct fileh *fh)
{
	printf("fh:\n"
			"\tinode:   %x\n"
			"\tspecial: %x\n"
			"\tfs:      %x\n"
			"\tperms:   %x\n"
			"\tflags:   %x\n"
			"\tdev:     %x\n"
			"\ttask:    %x\n",
			fh->inode,
			fh->special,
			fh->fs,
			fh->perms,
			fh->flags,
			fh->sdev.dev,
			fh->task);
}

struct mount *do_mount(struct block_dev *dev, char *point, struct fs_ops *fsops)
{
	struct mount *m = (struct mount *)kmalloc(sizeof(struct mount), "mount", NULL);

	printf("mount: [%x] on '%s' type '%s' ",
			dev ? dev->devid : 0,
			point,
			&fsops->name);

	m->dev = dev;
	m->ops = fsops;
	m->super = NULL;

	fsops->mount(m);

	m->next = mounts;
	mounts = m;

	if(!strcmp(point, "/")) { 
		printf("root");
		root = m;
	}

	printf("\n");
	return m;
}

struct mount *find_mount(char *name, char **newmount)
{
	int len = strlen(name);

	*newmount = kmalloc(len + 1,"mount", NULL);
	memcpy(*newmount, name + 1, len - 1);

	//printf("find_mount: %s -> %s\n", name, *newmount);

	return root;
}

uint64 do_write(struct fileh *fh, unsigned char *src, uint64 len)
{
	if(fh == NULL) {
		printf("do_write: fh == NULL\n");
		hlt();
	}
	//print_fh(fh);
	//printf("do_write: fh:%lx from:%lx len:%lx\n", fh, src, len);
	if(fh->special && (fh->flags & (FS_CHAR))) {
		if(fh->sdev.char_dev) {
			return fh->sdev.char_dev->ops->write(fh->sdev.char_dev, src, len);
		} else {
			printf("do_write: sdev is NULL!\n");
			hlt();
			return -1;
		}
	} else if( (fh->flags & FS_SOCKET) == FS_SOCKET ) {
	//	printf("socket\n");
		return 0;
	} else {
	//	printf("non-special\n");
		return fh->fs->ops->write(fh, src, len);
	}
}

uint64 do_read(struct fileh *fh, unsigned char *dst, uint64 len)
{
	uint64 ret;

	//printf("do_read: %lx - %lx [%lx]\n", dst, dst+len, len);

	//describe_mem((uint64)(dst+len));

	if(fh->special && ((fh->flags & FS_CHAR) == FS_CHAR)) {
		ret = fh->sdev.char_dev->ops->read(fh->sdev.char_dev, dst, len);
	} else if( fh->special && ((fh->flags & FS_BLOCK) == FS_BLOCK)) {
		ret = fh->sdev.blk_dev->ops->read(fh->sdev.blk_dev, dst, len, 
				fh->seek);
	} else if( fh->flags & FS_SOCKET ) {
		printf("do_read socket\n");
		ret = 0;
	} else {
		ret = fh->fs->ops->read(fh, dst, len);
	}

	return ret;
}

void do_seek(struct fileh *fh, uint64 off)
{
	if(fh->flags & FS_SOCKET) return;
	fh->seek = off;
}

uint64 do_close_socket(struct fileh *fh, struct task *this)
{
	return 0;
}

void do_close(struct fileh *fh, struct task *t)
{
	if(fh->special) {
	} else if(fh->flags & FS_SOCKET) {
		do_close_socket(fh, t);
	} else {
		fh->fs->ops->close(t, fh);
	}
	kfree(fh);
}

uint64 sys_read(uint64 fd, uint8 *data, uint64 len)
{
	struct task *this = &tasks[curtask];

	//printf("sys_read: fd=%x data=%x len=%x\n", fd, data, len);

	if(fd >= MAX_FD) return -EBADF;

	if(this->fps[fd]) {
		return do_read(this->fps[fd], data, len);
	} else {
		return -EBADF;
	}
}

uint64 sys_write(uint64 fd, uint8 *data, uint64 len)
{
	/*
	printf("sys_write: fd=%lx data=%lx len=%lx\n", 
			fd, 
			data, 
			len);
	*/
	struct task *t = &tasks[curtask];
	int err = -EBADF;

	if(fd >= MAX_FD) return -EBADF;

	if(t->fps[fd]) {
	//	printf("sys_write: about to do_write\n");
		err = do_write(t->fps[fd], data, len);
	} 

	//printf("sys_write: err=%x\n", err);

	return err;
}

uint64 sys_close(uint64 fd)
{
	struct task *this = &tasks[curtask];

	// printf("sys_close[%x]: %x\n", curtask, fd);
	
	if(fd >= MAX_FD || !this->fps[fd]) return -1;

	do_close(this->fps[fd], this);
	this->fps[fd] = NULL;

	return 0;
}

uint64 sys_socket(uint64 family, uint64 type, uint64 protocol)
{
	struct task *this = &tasks[curtask];
	uint64 i,found;

	printf("sys_socket: %x, %x, %x\n", family, type, protocol);

	for(i=0,found=(uint64)-1;i<MAX_FD;i++)
	{
		if(!this->fps[i]) {
			found=i;
			break;
		}
	}
	if(found == (uint64)-1) goto fail;

	this->fps[found] = do_socket(this, family, type, protocol);

	return found;

fail:
	return -1;
}

uint64 sys_listen(uint64 fd, uint64 listen)
{
	struct task *this = &tasks[curtask];
	if(fd >= MAX_FD || !this->fps[fd]) return -1;

	return do_listen(this, this->fps[fd], listen);
}

uint64 sys_accept(uint64 fd, struct sockaddr *sa, uint64 *len)
{
	struct task *this = &tasks[curtask];
	if(fd >= MAX_FD || !this->fps[fd]) return -1;
	//dump_task(this);

	return do_accept(this, this->fps[fd], sa, len);
}

uint64 sys_bind(uint64 fd, struct sockaddr *sa, uint64 len)
{
	struct task *this = &tasks[curtask];

	printf("sys_bind: %x, %x, %x\n", fd, sa, len);

	if(!sa || fd >= MAX_FD || !this->fps[fd]) return -1;

	return do_bind(this, this->fps[fd], sa, len);
}

uint64 sys_open(const char *name, int flags)
{
	struct task *this;
	uint64 i,found;

	this = &tasks[curtask];

	//printf("sys_open: name=%x flags=%x\n", name, flags);

	for(i=0,found=(uint64)-1;i<MAX_FD;i++)
	{
		if(!this->fps[i]) {
			found=i;
			break;
		}
	}

	if(found == (uint64)-1) {
		printf("sys_open: can't find fd\n");
		return -1;
	}

	this->fps[found] = do_open(name, this, flags);

	//printf("sys_open: fd=%x\n", found);

	return found;
}

struct fileh *do_dup(struct fileh *fh, struct task *t)
{
	struct fileh *ret;

	if(fh->flags & FS_SOCKET) {
		printf("do_dup: attempt to dup a socket\n");
		return NULL;
	}

	ret = kmalloc(sizeof(struct fileh), "fileh", t);

	ret->inode = fh->inode;
	ret->special = fh->special;
	ret->fs = fh->fs;
	ret->perms = fh->perms;
	ret->seek = fh->seek;
	ret->sdev.dev = fh->sdev.dev;
	ret->task = t;

	return ret;
}

struct fileh *do_open(const char *name, struct task *t, int flags)
{
	struct fileh *ret;
	struct mount *m;
	char *newname;

	//printf("do_open: name=%s ", name);

	m = find_mount((char *)name, &newname); 

	if(!m) return NULL;

	ret = kmalloc(sizeof(struct fileh), "fileh", t);
	if(ret == NULL) return NULL;

	ret->fs = m;
	ret->seek = 0;
	ret->perms = 0;
	ret->inode = m->ops->open(t, m, newname, ret);
	if(ret->special && ((ret->flags & FS_CHAR) == FS_CHAR)) {
		ret->sdev.char_dev = find_dev(ret->special, DEV_CHAR);
//		printf(" special:%x @ %x\n", ret->special, ret->sdev.char_dev);
	} else if(ret->special && ((ret->flags & FS_BLOCK) == FS_BLOCK)) {
		ret->sdev.blk_dev = find_dev(ret->special, DEV_BLOCK);
//		printf(" special:%x @ %x\n", ret->special, ret->sdev.blk_dev);
	} else if(ret->inode == -1) {
		kfree(ret);
		return NULL;
//		printf(" ret->inode: %x\n", ret->inode);
	}

	if(newname) kfree(newname);

	//print_fh(ret);

	return ret;
}
