#ifndef FAILFS_H
#define FAILFS_H

#define NULL_INO 0L
#define FFS_MAGIC_LEN 6

enum ffs_block_types {
	FFS_BT_SUPER = 1,
	FFS_BT_FILE  = 2,
	FFS_BT_DATA  = 3,
	FFS_BT_FREE  = 4
};

enum ffs_file_types {
	FFS_FT_DELETED = 0,
	FFS_FT_NORMAL  = 1,
	FFS_FT_DIR     = 2,
	FFS_FT_LINK    = 3,
	FFS_FT_SYMLINK = 4
};

typedef struct _ffs_superblock {
	unsigned char   magic[FFS_MAGIC_LEN] __attribute__((nonstring));
	unsigned short	block_type;

	unsigned short	block_size;		/* >= 512 */
	unsigned int	num_blocks;		/* max fs size is (2^32)*512 = 2TiB */
	unsigned short	root_block;		/* block containing / */
	unsigned short	free_block;		/* 1st block containing free block list */
}  __attribute__ ((packed)) ffs_superblock;


typedef struct _ffs_file_block {
	unsigned char   magic[FFS_MAGIC_LEN] __attribute__((nonstring));
	unsigned short	block_type;
	unsigned short  type;

	char			name[128];		/* type != FT_NORMAL */

	/* type != FT_NORMAL */
	unsigned int	child;			/* 1st child dirent             */
	unsigned int    parent;         /* containing directory entry   */
	unsigned int    next;           /* next peer dirent, 0 for none */
	unsigned int    target;			/* target inode                 */

	/* All */
	unsigned long   size;			/* directories are 0 */
	unsigned long	flags;
	unsigned int	owner;
	unsigned int	group;
	unsigned long	perms;
	unsigned short	major;
	unsigned short	minor;
	unsigned long	nlink;
	unsigned long	atime,mtime,ctime;
	unsigned int	data;			/* first data block  */

	unsigned long	res[4];
} __attribute__ ((packed)) ffs_file_block;

typedef struct _ffs_data_block {
	unsigned char	magic[FFS_MAGIC_LEN];
	unsigned short	block_type;

	unsigned short	len;			/* <= sb.block-size - header, elements in data */
	unsigned short  pad0;
	unsigned int	next;
	unsigned int	prev;
	unsigned int	head;			/* should be a ffs_file_block */
	unsigned long	res[4];

	unsigned char	data[] __attribute__((nonstring));

} __attribute__ ((packed)) ffs_data_block;

typedef struct _ffs_free_block {
	unsigned char   magic[FFS_MAGIC_LEN];
	unsigned short	block_type;

	unsigned short  len;		/* elements in data[] <= sb.block_size - header */
	unsigned short  pad0;
	unsigned int	next;		/* multiple free_blocks to cover entire device */
	unsigned int	prev;
	unsigned long	flags;
	unsigned long	res[4];

	unsigned long	data[];		/* bitfield: 64*4*8 = 2048 blocks */
} __attribute__ ((packed)) ffs_free_block;

#ifdef _KERNEL

#include <klibc.h>

struct failfs_private {
	uint64_t		num_free_blocks;
	uint64_t		free_cnt;
	uint64_t       *free_block;
	ino_t			first_normal_block;
	ffs_superblock  super;
	ffs_file_block  root;
};

extern const unsigned char ffs_magic[] __attribute__((nonstring));
extern const struct fs_ops failfs_ops;
#endif

#endif
