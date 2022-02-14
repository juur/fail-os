#ifndef _KERNEL
#define _KERNEL
#endif

#include "klibc.h"
#include "block.h"
#include "ram.h"
#include "mem.h"

//static struct ramdisk rds[NUM_RD];

__attribute__((nonnull)) static ssize_t rd_read_one(struct block_dev *b, char *target, off_t start)
{
	struct ramdisk *r = (struct ramdisk *)b->priv;
	memcpy((char *)target, (char *)&r->data[start], b->bsize);
	return b->bsize;
}

__attribute__((nonnull)) static ssize_t rd_write_one(struct block_dev *b, const char *source, off_t start)
{
	struct ramdisk *r = (struct ramdisk *)b->priv;
	memcpy((char *)&r->data[start], (char *)source, b->bsize);
	return b->bsize;
}

__attribute__((nonnull)) int rd_init(struct block_dev *b)
{
	struct ramdisk *r;
	if((r = kmalloc(sizeof(struct ramdisk), "ramdisk_priv", NULL, 0)) == NULL)
		goto fail;

	if((r->data = kmalloc(RD_SIZE, "ramdisk_data", NULL, 0)) == NULL)
		goto fail;
	
	r->length = RD_SIZE;
	b->bsize = 512;
	b->bcount = RD_SIZE/b->bsize;
	if(RD_SIZE % b->bsize) {
		printf("rd_init: error, RD_SIZE is not a mulitple of sector size\n");
		goto fail;
	}

	b->priv = r;

	return 0;
fail:
	if(r && r->data) kfree(r->data);
	if(r) kfree(r);
	return -1;
}

struct block_ops ram_block_ops = {
	"ram",
	rd_read_one,
	rd_write_one,
	rd_init,
	block_read
};


