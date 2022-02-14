#ifndef _FILE_H
#define _FILE_H

#include "klibc.h"
#include "proc.h"
#include "char.h"
#include "block.h"

#define SEEK_SET	0
#define SEEK_CUR	1
#define	SEEK_END	2
#define SEEK_DATA	3
#define SEEK_HOLE	4
#define SEEK_MAX	SEEK_HOLE

/* these are only used within the kernel */
#define FS_DIR  	0x001
#define FS_FILE 	0x002
#define FS_BLOCK    0x004
#define FS_CHAR 	0x008
#define FS_KERNEL	0x010
#define	FS_SOCKET	0x020
#define FS_BOUND	0x040
#define FS_LISTEN	0x080
#define FS_MOUNTED  0x100
#define FS_DELETED	0x200

/* these are used to communicate with userspace */
#define S_IFMT      0170000
#define S_IFSOCK    0140000
#define S_IFLNK     0120000
#define S_IFREG     0100000
#define S_IFBLK     0060000
#define S_IFDIR     0040000
#define S_IFCHR     0020000
#define S_IFIFO     0010000

#define S_ISUID     04000
#define S_ISGID     02000
#define S_ISVTX     01000
#define S_IRWXU     00700
#define S_IRUSR     00400
#define S_IWUSR     00200
#define S_IXUSR     00100
#define S_IRWXG     00070
#define S_IRGRP     00040
#define S_IWGRP     00020
#define S_IXGRP     00010
#define S_IRWXO     00007
#define S_IROTH     00004
#define S_IWOTH     00002
#define S_IXOTH     00001

#define S_ISREG(x)	((x)&S_IFREG)
#define S_ISDIR(x)	((x)&S_IFDIR)
#define S_ISCHR(x)	((x)&S_IFCHR)
#define S_ISBLK(x)	((x)&S_IFBLK)
#define S_ISFIFO(x)	((x)&S_IFIFO)
#define S_ISLNK(x)	((x)&S_IFLINK)
#define S_ISSOCK(x)	((x)&S_IFSOCK)

#define NAME_MAX	255
#define PATH_MAX	1024

struct fileh;
struct mount;
struct inode;
struct fsent;

/* fs_ops defines each occurance of a filesystem */

struct fs_ops {
	const char *const name;

	ssize_t (*read)  (struct fileh *,       char *, size_t, off_t)__attribute__((nonnull));
	ssize_t (*write) (struct fileh *, const char *, size_t, off_t)__attribute__((nonnull));

	int (*ioctl)     (struct task  *, struct fileh *, uint64_t request, ... )__attribute__((nonnull(2)));

	int (*mount)     (struct mount *) __attribute__((nonnull));
	int (*umount)    (struct mount *) __attribute__((nonnull));

	ino_t (*open)    (struct task  *, struct mount *, struct fsent *, struct fileh *, int, mode_t, void **)__attribute__((nonnull(2,3,4)));
	int   (*close)   (struct task  *, struct fileh *                                                        )__attribute__((nonnull(2)));

	int (*sync_inode)(struct inode *, ino_t, int)__attribute__((nonnull));
	int (*sync_fsent)(struct fsent *, int       )__attribute__((nonnull));

	int   (*find)    (struct task  *, struct mount *, struct fsent *, const char *  , struct fsent ** )__attribute__((nonnull(2,4,5)));
	ino_t (*create)  (struct task  *, struct mount *, struct fileh *, int, mode_t, dev_t, void **     )__attribute__((nonnull(2,3,7)));
	int   (*link)    (struct task  *, struct fsent *, ino_t                                           )__attribute__((nonnull(2)));
	ino_t (*mkdir)   (struct task  *, struct mount *, struct fsent *, const char *, mode_t            )__attribute__((nonnull(2,3,4)));
};

/* mount defines a specific mounted filesystem */

struct mount {
	struct mount        *next;
	struct block_dev    *dev;
	const struct fs_ops *ops;
	struct fsent        *root;
	struct fsent        *point;
	void                *super;
};

extern struct mount *mounts;
extern struct mount *root_mnt;
extern struct fsent *root_fsent;

/* inode is an abstract file on the system wide filesystem 
 * it is an in-memory representation of a file's metadata
 */

struct inode {
	struct inode *next;			/* global linked list of inodes       */
	struct mount *mnt;			/* device containing this inode   
	                             * for mount points this is the child
								 * not the parent */
	void         *priv;			/* private inode data from the fs     */
	struct inode *target;		/* for soft links                     */

	dev_t		st_dev;
	mode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;
	int			count;

	uint64_t	flags;
	blksize_t	st_blksize;
	blkcnt_t	st_blocks;
	ino_t		st_ino;
	off_t		st_size;
	time_t		st_atime;
	time_t		st_mtime;
	time_t		st_ctime;

	int			lock;
};

/* fsent is the name of the entry on the filesystems hierarchy that maps to an inode on a specific mount 
 * it is, simplistically, an in-memory only mapping if names to inodes
 */
struct fsent {
	struct fsent *next;		/* The list of fille fsent objects in the kernel    */
	struct fsent *parent;	/* The directory that this entry is within          */
	struct mount *fs;		/* the filesystem containing this fsent             */

	/* Any of these may be NULL until resolved */
	struct fsent *sibling;  /* The next entry in this directory                 */
	struct fsent *child;	/* in the case of soft links, this is the target    */
	struct inode *inode;	/* can be NULL */

	void   *priv;           /* file system specific directory entry information  */

	/* Used to resolve pointers NULL above */
	ino_t	ino;
	ino_t	sibling_ino;
	ino_t	child_ino;

	int		flags;
	int     count;
	int		lock;

	const char name[NAME_MAX];

	//struct mount *child_fs; /* the filesystem that children are placed in       */
};

/* fileh is a file handle, it defines a file (identified by an inode) on a specific
 * and manages operations on that file */
struct fileh {
	struct fsent *fsent;	/* the name used to open this file (NULL for sockets)        */
	struct inode *inode;	/* the inode the filehandle is attached to (NULL for sockets */
	struct fileh *listen_next;

	/* sdev is only used for special files */
	union {				
		struct block_dev *blk_dev;
		struct char_dev	 *char_dev;
		struct net_dev	 *net_dev;
		void			 *dev;
	} sdev;
	
	struct task		*task;	// NULL for kernel
	struct mount	*fs;	// ptr to fs structure, NULL for sockets
	void			*priv;	// file system private data

	/* specific to this handle */
	uint64_t	flags;	/* O_* */
	uint64_t	seek;		
	
	/* sys_socket params saved for forking a new socket */
	int			family;
	int			type;
	int			protocol;
};

#define O_RDONLY       00
#define O_WRONLY       01
#define O_RDWR         02
#define O_CREAT      0100
#define O_EXCL		 0200
#define O_NOCTTY	 0400
#define O_TRUNC     01000
#define O_APPEND    02000
#define O_NONBLOCK	04000
#define O_NDELAY	O_NONBLOCK

#define SYNC_READ	0x01
#define SYNC_WRITE	0x02

struct fsent *resolve_file(const char *const, struct fsent *, int *) __attribute__((nonnull(1,3)));
struct fileh *do_dup  (const struct fileh *, struct task *)__attribute__((nonnull(1)));
struct fileh *do_open (const char *, struct task *, int, mode_t, int *)__attribute__((nonnull(1)));
struct mount *do_mount(struct block_dev *, struct fsent *, const struct fs_ops *)__attribute__((nonnull(1,3)));
      ssize_t do_read (struct fileh *, char *dst, size_t len)__attribute__((nonnull));
      ssize_t do_write(struct fileh *, const char *src, size_t len)__attribute__((nonnull));
          int do_close(struct fileh *, struct task *t)__attribute__((nonnull(1)));
        off_t do_lseek(struct fileh *, off_t, int)__attribute__((nonnull));
          int do_mkdir(struct task *const tsk, const char *pathname, const mode_t mode);
struct inode *open_inode(struct mount *, ino_t inode, int *error) __attribute__((nonnull));
struct fsent *create_fsent(struct mount *, struct fsent *, ino_t, int *, const char *, bool)__attribute__((nonnull(1,4)));
void dump_fsents();
void flush_fsents();

void file_init(void);
#endif
// vim: set ft=c:
