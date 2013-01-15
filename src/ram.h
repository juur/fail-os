#ifndef	_RAM_H
#define _RAM_H

#define NUM_RD	1
#define RD_SIZE	0x10000

#define RD_MAJOR	0x01
#define	RD_0_MINOR	0x00

struct ramdisk {
	uint8	*data;
	uint32	length;
};

extern struct ramdisk rds[NUM_RD];
extern struct block_ops ram_block_ops;

#endif
