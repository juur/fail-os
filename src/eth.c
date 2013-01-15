#include "klibc.h"
#include "dev.h"
#include "pci.h"
#include "mem.h"
#include "eth.h"
#include "net.h"
#include "arp.h"
#include "ip.h"

uint8 eth_cnt = 0;
struct eth_dev *eths = NULL;

uint64 eth_write(struct fileh *fh, struct net_dev *nd, unsigned char *d, 
		uint64 len, uint32 proto)
{
	struct arp_entry *arp;
	uint8 mac[6];
	struct eth_dev *e = (struct eth_dev *)nd->priv;
	
	// printf("eth_write: len=%x\n", len);

	if(e == NULL) return -1;
	if(e->ops == NULL) return -1;
	if(proto == NETPROTO_IP) {
		struct ip_hdr *ip = (struct ip_hdr *)d;
		arp = find_arp_entry(ntohl(ip->dst));
		if(arp == NULL) {
			// do arp
			return -1;
		}
		memcpy(mac, mac, 6);
	}
	
	return e->ops->send(e, d, len, arp->mac);
}

uint64 eth_process(struct net_dev *nd)
{
	struct eth_dev *e = (struct eth_dev *)nd->priv;
	if(e == NULL) return -1;
	if(e->ops == NULL) return -1;
	return e->ops->poll(e, nd);
}

uint64 eth_init(struct net_dev *nd, void *phys, int type, struct net_proto *np)
{
	return 0;
}

uint64 eth_init_socket(struct fileh *fh, struct net_dev *nd)
{
	return 0;
}

struct net_ops eth_net_ops = {
	eth_write,
	eth_init,
	eth_init_socket,
	eth_process
};

struct eth_dev *eth_alloc(void *phys, struct eth_ops *ops)
{
	struct eth_dev *ret;
	struct dev *dev;

	printf("eth_alloc: ");

	printf("eth_dev ");
	ret = (struct eth_dev *)kmalloc(sizeof(struct eth_dev),"eth_dev", NULL);
	if(ret == NULL) goto fail;

	ret->phys = phys;
	ret->ops = ops;
	ret->unit = eth_cnt++;
	if(ret->unit == 255) goto fail2;

	printf("dev ");
	dev = add_dev(0, DEV_NET, &eth_net_ops, "eth", ret);
	if(dev == NULL) goto fail2;

	printf("init_netdev ");
	init_netdev(dev->op.net_dev, ret, 
			DEV_ETH, (struct net_proto *)find_dev(NETPROTO_IP, DEV_PROTO));

	dev->op.net_dev->ip.addr = 0xc0a80202;
	dev->op.net_dev->ip.netmask = 0xffffff00;

	printf("\n");

	ret->next = eths;
	eths = ret;

	return ret;

fail2:
	kfree(ret);
fail:
	printf("\n");
	return (struct eth_dev *)NULL;
}

void eth_free(struct eth_dev *e)
{
	struct eth_dev *prev = eths;

	while(prev) {
		if(prev->next == e) break;
		prev = prev->next;
	}

	if(prev) {
		prev->next = e->next;
	} else {
		eths = e->next;
	}

	// upper should do this!
	// free_netdev(dev->op.net_dev);
	// free_dev(dev);
	kfree(e);
}
