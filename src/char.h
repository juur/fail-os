#ifndef	_CHAR_H
#define	_CHAR_H

#include "klibc.h"
#include "block.h"

struct char_dev;

/* generic driver */

struct char_ops {
	uint64 (*read)(struct char_dev *, unsigned char *, uint64);
	uint64 (*write)(struct char_dev *, unsigned char *, uint64);
	bool (*init)(struct char_dev *);
	uint64 (*pending)(struct char_dev *);
};

/* specific char */

struct char_dev {
	uint64	devid;			// major|minor
	struct char_ops	*ops;	// block ops
	void	*private;		// private structure
};

#endif
