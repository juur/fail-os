#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <getopt.h>
#include <err.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "src/failfs.h"

static __attribute__((noreturn)) void show_usage()
{
	fprintf(stderr, "Usage: mkfs.ffs [-f] file|device\n");
	exit(EXIT_FAILURE);
}

static int opt_force   = 0;
static int opt_blksize = 0;

static void ffs_format(int fd, off_t bytes, int blksize)
{
	const ffs_superblock sb = {
		.magic      = "FAILFS",
		.block_type = FFS_BT_SUPER,
		.block_size = blksize,
		.num_blocks = bytes / blksize,
		.root_block = 3,
		.free_block = 4
	};

	if( lseek(fd, blksize * 2, SEEK_SET) == (off_t)-1 )
		err(EXIT_FAILURE, "lseek");

	if( write(fd, &sb, sizeof(sb)) != sizeof(sb) )
		err(EXIT_FAILURE, "write(superblock)");

    const ffs_file_block root = {
        .magic      = "FAILFS",
        .block_type = FFS_BT_FILE,
        .size       = 0,
        .type       = FFS_FT_DIR,
        .flags      = 0,
        .owner      = 0,
        .group      = 0,
        .perms      = 0755,
        .major      = 0,
        .minor      = 0,
        .atime      = time(0),
        .mtime      = time(0),
        .ctime      = time(0),
        .name       = "/",
        .child      = 0,
        .next       = 0,
        .parent     = 0,
    };

    if( lseek(fd, blksize * sb.root_block, SEEK_SET) == (off_t)-1 ) {
        err(EXIT_FAILURE, "lseek"); }

    if( write(fd, &root, sizeof(root)) != sizeof(root) ) {
		err(EXIT_FAILURE, "write(root)"); }

	const int fb_len = (blksize - sizeof(ffs_free_block));
	const int num_fb = sb.num_blocks / (fb_len * 64);

	printf("mkfs.failfs: %u free blocks required for %u total blocks of %u bytes\n", 
			num_fb,
			sb.num_blocks,
			blksize
			);

	ffs_free_block **fb;

	if( (fb = calloc(num_fb, sizeof(ffs_free_block *))) == NULL )
		err(EXIT_FAILURE, "calloc");

	for( int i = 0; i < num_fb; i++ )
	{
		if ( (fb[i] = calloc(1, sizeof(ffs_free_block) + fb_len)) == NULL )
			err(EXIT_FAILURE, "malloc");

		*fb[i] = (ffs_free_block){
			.magic = "FAILFS",
			.block_type = FFS_BT_FREE,
			.len = fb_len,
			.next = (i + 1 == num_fb) ? 0 : sb.free_block + i + 1,
			.prev = (i == 0) ? 0 : sb.free_block + i - 1,
			.flags = 0
		};
	}

	fb[0]->data[0] |= 0x1|0x2|0x4|0x8; /* boot sector, boot sector, superblock, root_block */

	//printf("fb_len = %d total = %d\n", fb_len, sizeof(ffs_free_block) + fb_len);

	/* n * free_blocks */
	for( int i = 0; i < num_fb; i++ )
		fb[0]->data[0] |= (1 << (i + 4));

	for( int i = 0; i < num_fb; i++ )
	{
		printf("mkfs.failfs: writing sector %d\n", (sb.free_block + i));

		if( lseek(fd, (sb.free_block + i) * blksize, SEEK_SET) == -1 )
			err(EXIT_FAILURE, "lseek");

		if( write(fd, fb[i], sizeof(ffs_free_block) + fb_len) != (int)(sizeof(ffs_free_block) + fb_len) )
			err(EXIT_FAILURE, "write(freeblock:%d)", i);
	}

	for( int i = 0; i < num_fb; i++ )
		if(fb[i])
			free(fb[i]);

	free(fb);
}

int main(int argc, char *argv[])
{
	int opt;
	while( (opt = getopt(argc, argv, "fb:")) != -1 )
	{
		switch( opt ) {
			case 'f':
				opt_force = 1;
				break;
			case 'b':
				opt_blksize = atoi(optarg);
				break;
			default:
				warnx("Unknown option '%c'\n", isprint(opt) ? opt : '?');
				show_usage();
		}
	}

	if( opt_blksize == 0 )
		opt_blksize = 512;

	if( (argc - optind) != 1 ) {
		warnx("Missing file or device\n");
		show_usage();
	}

	if( !opt_force )
		errx(EXIT_FAILURE, "please pass -f to erase file or device");

	int fd;

	if( (fd = open(argv[optind], O_RDWR)) == -1 )
		err(EXIT_FAILURE, "open: %s\n", argv[optind]);

	struct stat sb;

	if( fstat(fd, &sb) == -1 )
		err(EXIT_FAILURE, "stat: %s\n", argv[optind]);

	if( (sb.st_mode & S_IFMT) != S_IFREG )
		err(EXIT_FAILURE, "%s is not a regular file", argv[optind]);

	ffs_format(fd, sb.st_size, opt_blksize);

	close(fd);

	printf("mkfs.failfs: done\n");
}
