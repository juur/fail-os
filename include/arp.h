#ifndef _ARP_H
#define _ARP_H

#include "klibc.h"
#include "net.h"

struct arp_entry
{
	struct	arp_entry *next;
	uint32_t	ip;
	uint32_t	when;
	uint8_t	mac[6];
	struct	net_dev	*dev;
};

extern struct arp_entry *arptable;

struct arp_header
{
	uint16_t	htype;
	uint16_t	ptype;
	uint8_t	hlen;
	uint8_t	plen;
	uint16_t	oper;
}
#ifdef __GNUC__
    __attribute__((packed))
#endif
;

#define	HRD_ETHERNET	1

#define	ARP_REQUEST	1
#define	ARP_REPLY	2

void arp_scan(void);
void dump_arp(void);
void update_arp_entry(uint32_t ip, uint8_t mac[6], struct net_dev *nd);
struct arp_entry *find_arp_entry(uint32_t ip);
void arp_handle(struct net_dev *nd, uint8_t *data, uint64_t len);

#endif
