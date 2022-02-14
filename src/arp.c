#include "arp.h"
#include "klibc.h"
#include "mem.h"

struct arp_entry *arptable;

void print_mac(uint8_t *t);

struct arp_entry *find_arp_entry(uint32_t ip)
{
	struct arp_entry *t;

	//printf("find_arp_entry: ip=%x\n", ip);

	for( t = arptable ; t ; t=t->next )
		if(t->ip == ip) return t;

	return NULL;
}

void update_arp_entry(uint32_t ip, uint8_t mac[6], struct net_dev *nd)
{
	struct arp_entry *t;

	if(!(t = find_arp_entry(ip)))
	{
		t = kmalloc(sizeof(struct arp_entry), "arp_entry", NULL, 0);
		if(!t) {
			printf("update_arp_entry: kmalloc failed\n");
			return;
		}
		t->ip = ip;
		t->dev = nd;
		t->next = arptable;
		arptable = t;
	}
	memcpy(t->mac, mac, sizeof(t->mac));

	//dump_arp();
}

void arp_scan()
{
	struct arp_entry *t;

	for( t = arptable ; t ; t=t->next )
	{
		// expire here
	}
}

void arp_handle(struct net_dev *nd, uint8_t *data, uint64_t len)
{
	struct arp_header *hdr = (struct arp_header *)data;
	printf("arp_handle: htype=%x, ptype=%x, hlen=%x, plen=%x, oper=%x\n",
			hdr->htype,
			hdr->ptype,
			hdr->hlen,
			hdr->plen,
			hdr->oper);
}

void dump_arp()
{
	struct arp_entry *t;

	for( t = arptable ; t ; t=t->next )
	{
		printf("dump_arp: %0x ", t->ip);
		print_mac(t->mac);
		printf("\n");
	}
}
