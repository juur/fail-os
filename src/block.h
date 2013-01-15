#ifndef	_BLOCK_H
#define	_BLOCK_H

#include "klibc.h"

struct block_dev;

/* the "driver" e.g. ramdisk, read/write_one = 1 sector */

struct block_ops {
	uint64 (*read_one)(struct block_dev *d, uint8 *data, uint64 sector);
	uint64 (*write_one)(struct block_dev *d, uint8 *data, uint64 sector);
	void (*init)(struct block_dev *);
	uint64 (*read)(struct block_dev *d, uint8 *data, uint64 off, uint64 len);
};

/* the specific block dev, e.g. /dev/ram1 */

struct block_dev {
	struct	bio_req		*req;
	struct 	block_ops	*ops;		// block ops
	uint64				 bsize;
	uint64				 bcount;
	uint64				 devid;		// major|minor
	void				*private;	// private structure
};

uint64 block_read(struct block_dev *dev, uint8 *dst, uint64 len, uint64 off);
void bio_poll(void);

#endif
