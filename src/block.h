#ifndef	_BLOCK_H
#define	_BLOCK_H

#include "klibc.h"

struct block_dev;

/* the "driver" e.g. ramdisk, read/write_one = 1 sector */

struct block_ops {
	const char *const name;

	ssize_t (*read_one)(struct block_dev *d, char *data, off_t sector)__attribute__((nonnull));
	ssize_t (*write_one)(struct block_dev *d, const char *data, off_t sector)__attribute__((nonnull));
	int (*init)(struct block_dev *)__attribute__((nonnull));
	ssize_t (*read)(struct block_dev *d, char *data, size_t, off_t)__attribute__((nonnull));
};

/* the specific block dev, e.g. /dev/ram1 */

struct block_dev {
	struct	bio_req			*req;
	const struct block_ops	*ops;		// block ops

	uint32_t  bsize;
	dev_t     devid;   // major|minor
	uint64_t  bcount;
	void	 *priv;	   // private structure
};

ssize_t block_read(struct block_dev *, char *, size_t, off_t)__attribute__((nonnull));
ssize_t block_write(struct block_dev *, const char *, size_t, off_t)__attribute__((nonnull));
void bio_poll(void);

#endif
// vim: set ft=c:
