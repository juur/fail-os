#include "ip.h"
#include "mem.h"
#include "udp.h"

ssize_t udp_send(const void *data, size_t len, uint64_t flags)
{
	return -ENOMEM;
}

ssize_t udp_recv(struct net_dev *nd, uint32_t src, uint32_t dst,
		void *data, size_t len, struct ip_hdr *iph)
{
	struct udp_hdr *hdr = (struct udp_hdr *)data;

	hdr->src_port = ntohs(hdr->src_port);
	hdr->dst_port = ntohs(hdr->dst_port);
	hdr->length   = ntohs(hdr->length);

	printf("udp_recv: %x:%u -> %x:%u length:%d\n",
			src,
			hdr->src_port,
			dst,
			hdr->dst_port,
			hdr->length);

	return -ENOMEM;
}
