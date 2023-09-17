#ifndef _ETH_H
#define _ETH_H

#include "klibc.h"
#include "net.h"

struct eth_dev;

struct eth_ops {
	const char *const name;

	uint64_t (*open)(struct eth_dev *d) __attribute__((nonnull));
	uint64_t (*close)(struct eth_dev *d) __attribute__((nonnull));
	uint64_t (*poll)(struct eth_dev *d, struct net_dev *nd) __attribute__((nonnull));
	uint64_t (*send)(struct eth_dev *, char *, uint16_t, uint8_t dst[6]) __attribute__((nonnull));
};

struct eth_dev {
	struct	eth_dev	*next;
	uint8_t	addr[6];
	uint8_t	unit;
	void	*phys;
	const struct eth_ops	*ops;
	struct dev				*dev;
};

struct eth_dev *eth_alloc(void *phys, const struct eth_ops *ops);
void eth_free(struct eth_dev *e);

#define ETHPROTO_IP		0x0800
#define	ETHPROTO_ARP	0x0806
#define ETHPROTO_VLAN	0x8100

#endif
// vim: set ft=c:
