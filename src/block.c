#include "block.h"
#include "dev.h"
#include "klibc.h"
#include "cpu.h"
#include "mem.h"

struct sector {
	struct sector 	*next;
	struct bio_req 	*req;
	uint64 			 len;
	uint64 			 sector;
	uint8  			*data;
};

struct bio_req {
	struct bio_req		*next;
	struct sector 		*first,*last,*cur;
	struct block_dev 	*dev;
	struct task 		*owner;
	uint64				 flags;
	uint64  			 len;
	uint64				 offset;
	uint8  				*data;
};

#define	BIO_READ	(1 << 0)
#define	BIO_WRITE	(1 << 1)
#define BIO_BIGBUF	(1 << 2)
#define	BIO_CLEAN	(1 << 3)
#define BIO_BIGSEC	(1 << 4)
#define BIO_DONE	(1 << 5)
#define BIO_ERROR	(1 << 6)

extern struct dev *devs;

void bio_signal_done(struct bio_req *req)
{
	req->flags |= BIO_DONE;
}

void bio_proc_read(struct bio_req *req)
{
	if(req->dev->ops->read_one(req->dev, req->cur->data, 
				req->cur->sector) != req->cur->len) {
		req->flags |= BIO_ERROR;
		bio_signal_done(req);
		return;
	}

	req->cur = req->cur->next;
	if(!req->cur) bio_signal_done(req);
}

void bio_proc_write(struct bio_req *req)
{
	printf("bio_proc_write: not implemented\n");
	hlt();
}

void bio_proc_one(struct bio_req *req)
{
	printf("bio_proc_one: req=%x\n", req);

	if(req->flags & BIO_CLEAN) {
		if(req->flags & BIO_BIGBUF) kfree(req->first->data);
		if(req->flags & BIO_BIGSEC) kfree(req->first);
		if(req->dev->req == req) req->dev->req = req->next;
		kfree(req);
	} else if(req->flags & BIO_READ) {
		bio_proc_read(req);
	} else if(req->flags & BIO_WRITE) {
		bio_proc_write(req);
	} else {
		printf("bio_proc_one: bio_req unknown type=%x\n", req->flags);
		req->flags |= BIO_CLEAN|BIO_DONE;
	}
}

void bio_proc(struct block_dev *dev)
{
	struct bio_req *req, *next;

	if(!dev) return;

	for(req = dev->req ; req ; )
	{
		next = req->next;
		if(!(req->flags & BIO_DONE)) bio_proc_one(req);
		req = next;
	}
}

void bio_poll()
{
	struct dev *d;

	for(d = devs; d; d=d->next)
	{
		if(d->type != DEV_BLOCK) continue;
		bio_proc(d->op.bl_dev);
	}
}


struct bio_req *bio_do_req(struct block_dev *dev, struct task *owner, 
		uint64 req, uint64 flags, uint64 len, uint64 offset, uint8 *data)
{
	struct bio_req *ret;
	uint64 bsize,i,bcnt;
	struct sector *tmp;
	uint8 *buffer;

	printf("bio_do_req: dev=%x tsk=%x req=%x flags=%x l=%x o=%x d=%x\n",
			dev, owner, req, flags, len, offset, data);

	if(!dev || !data || !req) return NULL;

	ret = kmalloc(sizeof(struct bio_req), "bio_req", owner);
	if(!ret) {
		printf("bio_do_req: unable to kmalloc bio_req\n");
		return NULL;
	}

	bsize = dev->bsize;
	bcnt = (len+bsize-1)/bsize;

	ret->owner = owner;
	ret->flags = req|flags;
	ret->len = len;
	ret->offset = offset;
	ret->data = data;
	ret->dev = dev;

	switch(req)
	{
		case BIO_READ:
			printf("bio_do_req: read\n");
			ret->flags |= BIO_BIGBUF|BIO_BIGSEC;
			buffer = kmalloc(bsize * bcnt, "sectordata[]", owner);
			tmp = kmalloc(sizeof(struct sector) * bcnt, "sector[]", owner);
			for(i=0;i<bcnt;i++) {
				if(i<bcnt-1) tmp[i].next = &tmp[i+1];
				tmp[i].req = ret;
				tmp[i].len = bsize;
				tmp[i].sector = offset + i;
				tmp[i].data = (uint8 *)(buffer + (bcnt*i));
			}
			ret->first = ret->cur = &tmp[0];
			ret->last = &tmp[bcnt-1];
			break;
		case BIO_WRITE:
			printf("bio_do_req: write\n");
			ret->flags |= BIO_BIGSEC;
			tmp = kmalloc(sizeof(struct sector) * bcnt, "sector[]", owner);
			for(i=0;i<bcnt;i++) {
				if(i<bcnt-1) tmp[i].next = &tmp[i+1];
				tmp[i].req = ret;
				tmp[i].len = bsize;
				tmp[i].sector = offset + i;
				tmp[i].data = (uint8 *)(data + (bcnt*i));
			}
			ret->first = ret->cur = &tmp[0];
			ret->last = &tmp[bcnt-1];
			break;
		default:
			printf("do_req: unknown req=%x\n", req);
			kfree(ret);
			return NULL;
	}
	return ret;
}

void print_block(struct block_dev *dev)
{
	printf( "print_block: req=%x ops=%x bsize=%x\n"
			"print_block: bcount=%x devid=%x private=%x\n"
			,
			dev->req, dev->ops, dev->bsize,
			dev->bcount, dev->devid, dev->private
			);
}

uint64 block_read(struct block_dev *dev, uint8 *dst, uint64 len, uint64 off)
{
	struct bio_req *req;

	printf("block_read: dev=%x, dst=%x, len=%x, off=%x\n", dev, dst, len, off);

	req = bio_do_req(dev, &tasks[curtask], BIO_READ, 0, len, off, dst);
	req->next = dev->req;
	dev->req = req;

	printf("block_read: req=%x\n", req);
	sti();
	while(!(req->flags & BIO_DONE)) hlt();
	req->flags |= BIO_CLEAN;
	printf("block_read: finished\n");
	return 0;
}
