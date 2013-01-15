#ifndef _ARP_H
#define _ARP_H

#include "klibc.h"
#include "net.h"

struct arp_entry
{
	struct	arp_entry *next;
	uint32	ip;
	uint32	when;
	uint8	mac[6];
	struct	net_dev	*dev;
};

extern struct arp_entry *arptable;

struct arp_header
{
	uint16	htype;
	uint16	ptype;
	uint8	hlen;
	uint8	plen;
	uint16	oper;
}
#ifdef __GNUC__
    __attribute__((packed))
#endif
;

#define	HRD_ETHERNET	1

#define	ARP_REQUEST	1
#define	ARP_REPLY	2

void arp_scan();
void dump_arp();
void update_arp_entry(uint32 ip, uint8 mac[6], struct net_dev *nd);
struct arp_entry *find_arp_entry(uint32 ip);
void arp_handle(struct net_dev *nd, uint8 *data, uint64 len);

#endif
