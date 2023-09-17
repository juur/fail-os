#ifndef _NET_H
#define _NET_H

#include <klibc.h>
#include <file.h>

//extern struct net_dev *netdevs;

struct net_dev;
struct net_proto;

struct net_ops {
	const char *const name;

	uint64_t (*write)(struct fileh *fh, struct net_dev *, char *, uint64_t, uint32_t dst_ip);
	uint64_t (*init)(struct net_dev *, void *phys, int type, struct net_proto *);
	uint64_t (*init_socket)(struct fileh *fh, struct net_dev *);
	uint64_t (*process)(struct net_dev *);
};

struct net_proto_ops {
	const char *const name;

	uint64_t (*init)(struct net_proto *)__attribute__((nonnull));
	uint64_t (*recv)(struct net_dev *nd, struct net_proto *, char *, uint64_t);
	uint64_t (*ioctl)(struct fileh *f, int cmd, void *arg);
};

struct net_proto {
	struct net_proto			*next;
	const struct net_proto_ops	*ops;
	uint32_t	padding[16];
};

struct net_dev;

struct ip_addr {
    uint32_t addr;
    uint32_t netmask;
    uint32_t bcast;
    struct net_dev *dev;
};

struct net_dev {
	const struct net_ops		*ops;
	struct net_dev				*next;
	struct net_proto			*upper;
	void						*priv;

	int		 type;
	uint16_t state;
	uint16_t mtu;

	struct ip_addr	ip;
};

typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[];
};

struct linger {
	int l_onoff;
	int l_linger;
};

#define SOCK_DGRAM     1
#define SOCK_RAW       2
#define SOCK_SEQPACKET 3
#define SOCK_STREAM    4

#define SOL_SOCKET     1

#define SO_ACCEPTCONN   1
#define SO_BROADCAST    2
#define SO_DEBUG        3
#define SO_DONTROUTE    4
#define SO_ERROR        5
#define SO_KEEPALIVE    6
#define SO_LINGER       7
#define SO_OOBINLINE    8
#define SO_RCVBUF       9
#define SO_RCVLOWAT     10
#define SO_RCVTIMEO     11
#define SO_SNDBUF       12
#define SO_SNDLOWAT     13
#define SO_SNDTIMEO     14
#define SO_TYPE         15

#define SOMAXCONN       32

#define AF_INET     1
#define AF_INET6    2
#define AF_UNIX     3
#define AF_UNSPEC   4

#define	NET_NEW		0
#define	NET_READY	1

#define	NETDEV_NULL	0
#define NETDEV_PPP	1
#define	NETDEV_SLIP	2
#define NETDEV_ETH	3

#define	NETPROTO_NULL	0	
#define	NETPROTO_IP	1

uint64_t init_netdev(struct net_dev *nd, void *phys, int type, struct net_proto *up);
void net_loop(void);
struct net_dev *find_dev_ip(uint32_t ip);
struct fileh *find_listen(uint16_t family, struct sockaddr *sa, uint16_t proto);
int do_accept(struct task *this_task, struct fileh *f, struct sockaddr *sa, socklen_t *len);
int do_listen(struct task *this_task, struct fileh *f, int32_t listen);
int do_bind(struct task *this_task, struct fileh *f, struct sockaddr *sa, socklen_t len);
struct fileh *do_socket(struct task *this_task, int family, int type, int proto, long *err);

#endif
// vim: set ft=c:
