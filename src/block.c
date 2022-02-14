#include "block.h"
#include "dev.h"
#include "klibc.h"
#include "cpu.h"
#include "mem.h"

struct sector {
	struct sector 	*next;
	struct bio_req 	*req;
	ssize_t 		 len;
	uint64_t 		 sector;
	char	  		*data;
};

struct bio_req {
	struct bio_req		*next;
	struct sector 		*first,*last,*cur;
	struct sector       *sectors;
	void                *sector_data;
	struct block_dev 	*dev;
	struct task 		*owner;
	uint64_t			 flags;
	ssize_t  			 len;
	ssize_t				 processed;
	uint64_t			 offset;
	char	  			*data;
	int                  errn;
};

#define	BIO_READ	(1 << 0)
#define	BIO_WRITE	(1 << 1)
#define BIO_BIGBUF	(1 << 2)
#define	BIO_CLEAN	(1 << 3)
#define BIO_BIGSEC	(1 << 4)
#define BIO_DONE	(1 << 5)
#define BIO_ERROR	(1 << 6)

extern struct dev *devs;

void bio_signal_done(struct bio_req *const req)
{
	req->flags |= BIO_DONE;
}

ssize_t bio_proc_read(struct bio_req *const req)
{
	if(req == NULL)
		return -EINVAL;

	int rc;
	if((rc = req->dev->ops->read_one(req->dev, req->cur->data, 
				req->cur->sector) < 0)) {
		req->flags |= BIO_ERROR;
		req->errn   = rc;
		bio_signal_done(req);
		return rc;
	}

	req->processed += rc;
	req->cur        = req->cur->next;

	if(!req->cur)
		bio_signal_done(req);

	return 0;
}

ssize_t bio_proc_write(struct bio_req *const req)
{
	if(req == NULL)
		return -EINVAL;

	int rc;
	if((rc = req->dev->ops->write_one(req->dev, req->cur->data,
					req->cur->sector) < 0)) {
		req->flags |= BIO_ERROR;
		req->errn   = rc;
		bio_signal_done(req);
		return rc;
	}

	req->processed += rc;
	req->cur        = req->cur->next;

	if(!req->cur)
		bio_signal_done(req);

	return 0;
}

int bio_proc_one(struct bio_req *const req)
{
	printf("bio_proc_one: req=%p\n", (void *)req);

	if(req->flags & BIO_CLEAN) {
		if(req->sector_data && (req->flags & BIO_BIGBUF)) kfree(req->sector_data);
		if(req->sectors     && (req->flags & BIO_BIGSEC)) kfree(req->sectors);
		if(req->dev->req == req) req->dev->req = req->next;
		kfree(req);
		return 0;
	} else if(req->flags & BIO_READ) {
		return bio_proc_read(req);
	} else if(req->flags & BIO_WRITE) {
		return bio_proc_write(req);
	} else {
		printf("bio_proc_one: bio_req unknown type=%lx\n", req->flags);
		req->flags |= BIO_CLEAN|BIO_DONE;
		return -1;
	}
}

void bio_proc(struct block_dev *const dev)
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
		if(d->type != DEV_BLOCK) 
			continue;

		bio_proc(d->op.bl_dev);
	}
}


struct bio_req *bio_do_req(struct block_dev *const dev, 
		struct task *const owner, 
		const uint64_t req, 
		const uint64_t flags, 
		const uint64_t len, 
		const uint64_t offset, 
		char *const data)
{
	struct bio_req *ret;
	uint64_t bsize,i,bcnt;
	struct sector *tmp;
	uint8_t *buffer;

	printf("bio_do_req: dev=%p tsk=%p req=%lx flags=%lx l=%lx o=%lx d=%p\n",
			(void *)dev, (void *)owner, req, flags, len, offset, (void *)data);

	if(!dev || !data || !req) 
		return NULL;

	if((ret = kmalloc(sizeof(struct bio_req), "bio_req", owner, 0)) == NULL) {
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
			ret->sector_data = buffer = kmalloc(bsize * bcnt, "sectordata[]", owner, 0);
			ret->sectors     = tmp    = kmalloc(sizeof(struct sector) * bcnt, "sector[]", owner, 0);

			for(i=0;i<bcnt;i++) {
				if(i<bcnt-1) tmp[i].next = &tmp[i+1];
				tmp[i].req = ret;
				tmp[i].len = bsize;
				tmp[i].sector = offset + i;
				tmp[i].data = (char *)(buffer + (bcnt*i));
			}

			ret->first = &tmp[0];
			ret->cur   = &tmp[0];
			ret->last  = &tmp[bcnt-1];
			break;

		case BIO_WRITE:
			printf("bio_do_req: write\n");
			ret->flags |= BIO_BIGSEC;
			ret->sectors = tmp = kmalloc(sizeof(struct sector) * bcnt, "sector[]", owner, 0);

			for(i=0;i<bcnt;i++) {
				if(i<bcnt-1) tmp[i].next = &tmp[i+1];
				tmp[i].req = ret;
				tmp[i].len = bsize;
				tmp[i].sector = offset + i;
				tmp[i].data = (char *)(data + (bcnt*i));
			}

			ret->first = &tmp[0];
			ret->cur   = &tmp[0];
			ret->last  = &tmp[bcnt-1];
			break;

		default:
			printf("do_req: unknown req=%lx\n", req);
			kfree(ret);
			return NULL;
	}

	return ret;
}

void print_block(struct block_dev *dev)
{
	printf( "print_block: req=%p ops=%p bsize=%x\n"
			"print_block: bcount=%lx devid=(%x,%x) private=%p\n"
			,
			(void *)dev->req,
			(void *)dev->ops,
			dev->bsize,
			dev->bcount,
			DEV_MAJOR(dev->devid),
			DEV_MINOR(dev->devid),
			dev->priv
			);
}

ssize_t block_read(struct block_dev *dev, char *dst, size_t len, off_t off)
{
	struct bio_req *req;

	if(len == 0)
		return 0;

	printf("block_read: dev=%p, dst=%p, len=%lx, off=%lx\n", (void *)dev, (void *)dst, len, off);

	req = bio_do_req(dev, &tasks[curtask], BIO_READ, 0, len, off, dst);
	req->next = dev->req;
	dev->req = req;

	printf("block_read: req=%p\n", (void *)req);

	sti(); {
		while(!(req->flags & BIO_DONE)) hlt();
	} cli();

	req->flags |= BIO_CLEAN;
	printf("block_read: finished\n");
	return req->processed;
}

ssize_t block_write(struct block_dev *dev, const char *src, size_t len, off_t off)
{
	struct bio_req *req;

	if(len == 0)
		return 0;

	req = bio_do_req(dev, &tasks[curtask], BIO_WRITE, 0, len, off, (char *)src);
	req->next = dev->req;
	dev->req = req;

	sti(); {
		while(!(((volatile struct bio_req *)req)->flags & BIO_DONE)) hlt();
	} cli();

	req->flags |= BIO_CLEAN;
	printf("block_write: finished\n");
	return req->processed;
}
