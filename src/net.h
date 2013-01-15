#ifndef _NET_H
#define _NET_H

#include "klibc.h"
#include "file.h"

extern struct net_dev *netdevs;

struct net_dev;
struct net_proto;

struct net_ops {
	uint64 (*write)(struct fileh *fh, struct net_dev *, unsigned char *, uint64, uint32 dst_ip);
	uint64 (*init)(struct net_dev *, void *phys, int type, struct net_proto *);
	uint64 (*init_socket)(struct fileh *fh, struct net_dev *);
	uint64 (*process)(struct net_dev *);
};

struct net_proto_ops {
	uint64 (*init)(struct net_proto *);
	uint64 (*recv)(struct net_dev *nd, struct net_proto *, uint8 *, uint64);
};

struct net_proto {
	struct net_proto *next;
	struct net_proto_ops	*ops;
	uint32	padding[16];
};

struct net_dev;

struct ip_addr {
    uint32 addr;
    uint32 netmask;
    uint32 bcast;
    struct net_dev *dev;
};

struct net_dev {
	struct net_ops		*ops;
	struct net_dev		*next;
	struct net_proto	*upper;
	void				*priv;
	int					 type;
	uint16				 state;
	struct ip_addr		ip;
};

struct sockaddr;

#define	NET_NEW		0
#define	NET_READY	1

#define	NETDEV_NULL	0
#define NETDEV_PPP	1
#define	NETDEV_SLIP	2
#define NETDEV_ETH	3

#define	NETPROTO_NULL	0	
#define	NETPROTO_IP	1

uint64 init_netdev(struct net_dev *nd, void *phys, int type, struct net_proto *up);
void net_loop();
struct net_dev *find_dev_ip(uint32 ip);
struct fileh *find_listen(uint16 family, struct sockaddr *sa, uint16 proto);
uint64 do_accept(struct task *this_task, struct fileh *f, struct sockaddr *sa, uint64 *len);
uint64 do_listen(struct task *this_task, struct fileh *f, uint64 listen);
uint64 do_bind(struct task *this_task, struct fileh *f, struct sockaddr *sa, uint64 len);
struct fileh *do_socket(struct task *this_task, uint64 family, uint64 type, uint64 proto);

#endif
