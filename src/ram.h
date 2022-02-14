#ifndef	_RAM_H
#define _RAM_H

#include "klibc.h"

#define NUM_RD	1
#define RD_SIZE	0x10000

#define RD_MAJOR	0x01
#define	RD_0_MINOR	0x00

struct ramdisk {
	unsigned char	*data;
	uint32_t		 length;
};

extern struct block_ops ram_block_ops;

#endif
// vim: set ft=c:
