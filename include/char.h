#ifndef	_CHAR_H
#define	_CHAR_H

#include "klibc.h"
#include "block.h"
#include "proc.h"

struct char_dev;

/* generic driver */

struct char_ops {
	const char *const name;

	ssize_t (*read)   (struct char_dev *, char *, size_t)__attribute__((nonnull));
	ssize_t (*write)  (struct char_dev *, const char *, size_t)__attribute__((nonnull));
	int     (*init)   (struct char_dev *)__attribute__((nonnull));
	ssize_t (*pending)(struct char_dev *)__attribute__((nonnull));
	int     (*ioctl)  (struct char_dev *, struct task *, unsigned long, unsigned long)__attribute__((nonnull));
};

/* specific char */

struct char_dev {
	uint64_t	             devid; // major|minor
	const struct char_ops	*ops;   // block ops
	void	                *priv;  // private structure
};

#endif
// vim: set ft=c:
