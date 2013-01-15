#include "klibc.h"
#include "block.h"
#include "ram.h"
#include "mem.h"

struct ramdisk rds[NUM_RD];

uint64 rd_read_one(struct block_dev *b, uint8 *target, uint64 start)
{
	struct ramdisk *r = (struct ramdisk *)b->private;
	memcpy((char *)target, (char *)&r->data[start], b->bsize);
	return b->bsize;
}

uint64 rd_write_one(struct block_dev *b, uint8 *source, uint64 start)
{
	struct ramdisk *r = (struct ramdisk *)b->private;
	memcpy((char *)&r->data[start], (char *)source, b->bsize);
	return b->bsize;
}

void rd_init(struct block_dev *b)
{
	struct ramdisk *r = (struct ramdisk *)b->private;
	//printf("rd_init\n");
	r->data = kmalloc(RD_SIZE, "ramdisk", NULL);
	r->length = RD_SIZE;
	b->bsize = 512;
	b->bcount = RD_SIZE/b->bsize;
	if(RD_SIZE % b->bsize) 
		printf("rd_init: error, RD_SIZE is not a mulitple of sector size\n");
}

struct block_ops ram_block_ops = {
	rd_read_one,
	rd_write_one,
	rd_init,
	block_read
};


