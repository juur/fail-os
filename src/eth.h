#ifndef _ETH_H
#define _ETH_H

#include "klibc.h"
#include "net.h"

struct eth_dev;

struct eth_ops {
	uint64 (*open)(struct eth_dev *d);
	uint64 (*close)(struct eth_dev *d);
	uint64 (*poll)(struct eth_dev *d, struct net_dev *nd);
	uint64 (*send)(struct eth_dev *, uint8 *, uint64, uint8 dst[6]);
};

struct eth_dev {
	struct	eth_dev	*next;
	uint8	addr[6];
	uint8	unit;
	void	*phys;
	struct eth_ops	*ops;
	struct dev		*dev;
};

struct eth_dev *eth_alloc(void *phys, struct eth_ops *ops);
void eth_free(struct eth_dev *e);

#define ETHPROTO_IP		0x0800
#define	ETHPROTO_ARP	0x0806

#endif
