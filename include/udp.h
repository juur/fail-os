#ifndef _UDP_H
#define _UDP_H

#include "ip.h"

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t chksum;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
;

struct udp_phdr {
}
#ifdef __GNUC__
__attribute__((packed))
#endif
;

extern ssize_t udp_recv(struct net_dev *nd, uint32_t src, uint32_t dst,
          void *data, size_t len, struct ip_hdr *iph);

#endif
