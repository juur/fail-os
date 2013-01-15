typedef struct _kfs_superblock {
	unsigned long	magic;
	unsigned short	block_type;

	unsigned short	block_size;		/* >= 512 */

	unsigned short	num_blocks;		/* max fs size is 65535*256*512 = 8GiB */
	unsigned short	pad0;			/* res: 32bit num_blocks */
	unsigned char	root_block;		/* block containing / */
	unsigned char	free_block;		/* block containing free block list */
	unsigned char	data[0];

}  __attribute__ ((packed)) kfs_superblock;

typedef struct _kfs_file_block {
	unsigned long	magic;
	unsigned short	block_type;

	unsigned long	flags;
	unsigned long	owner;
	unsigned long	group;
	unsigned long	perms;
	unsigned long	major;
	unsigned long	minor;
	unsigned long	atime,mtime,ctime;

	unsigned char	name[128];

	unsigned char	first;
	unsigned char	pad[3];

	unsigned long	res[4];
	unsigned char	data[0];

} __attribute__ ((packed)) kfs_file_block;

typedef struct _kfs_data_block {
	unsigned long	magic;
	unsigned short	block_type;

	unsigned short	len;
	unsigned char	next;
	unsigned char	prev;
	unsigned char	head;
	unsigned char	pad0;
	unsigned long	res[4];
	unsigned char	data[0];

} __attribute__ ((packed)) kfs_data_block;

typedef struct _kfs_free_block {
	unsigned long	magic;
	unsigned short	block_type;

	unsigned char	next;
	unsigned char	flags;
	unsigned char	prev;
	unsigned short	pad;

	unsigned long	data[64];		/* 64*4*8 = 2048 blocks */
} __attribute__ ((packed)) kfs_free_block;
