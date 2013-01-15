#include "ip.h"
#include "mem.h"
#include "net.h"

struct fileh *listen = NULL;


uint64 ip_init(struct net_proto *np)
{
	listen = NULL;
	return 0;
}

struct fileh *find_listen_ip(struct sockaddr_in *sin, uint32 proto)
{
	struct fileh *f;
	struct ip_sock *ips;

	/*
	printf("find_listen_ip: {%u, %u, %u} %u\n",
			sin->sin_family,
			sin->sin_port,
			sin->sin_addr.s_addr,
			proto);
			*/

	for( f = listen ; f ; f=f->listen_next )
	{
		ips = (struct ip_sock *)f->priv;


		if(f->family != AF_INET) continue;
		if((f->flags & (FS_LISTEN|FS_SOCKET)) != (FS_LISTEN|FS_SOCKET) ) continue;
		if(!ips || ips->proto != proto) continue;
		if(sin->sin_addr.s_addr != INADDR_ANY && 
				sin->sin_addr.s_addr != ips->local.sin_addr.s_addr) continue;
		if(sin->sin_port != ips->local.sin_port) continue;
		if(ips->state != IPS_LISTEN) continue;
		return f;
	}

	return NULL;
}

void dump_listen()
{
	struct fileh *f;
	struct ip_sock *ips;

	for( f = listen ; f ; f=f->listen_next )
	{
		if(f->family != AF_INET) continue;
		ips = (struct ip_sock *)f->priv;
		printf("dump_listen: p:%u local={%u,%u,%u} state=%u\n",
				ips->proto,
				ips->local.sin_family,
				ips->local.sin_port,
				ips->local.sin_addr.s_addr,
				ips->state);
	}
}

uint64 add_listen(struct fileh *f)
{
	f->listen_next = listen;
	listen = f;
	dump_listen();
	return 0;
}

uint64 ip_accept(struct fileh *f, struct fileh *newf, struct sockaddr_in *sin, uint64 *len)
{
	struct ip_sock *ips = (struct ip_sock *)f->priv;
	struct ip_sock *new_ips = (struct ip_sock *)newf->priv;

	if(ips->state != IPS_LISTEN || ips->s.tcp->state != LISTEN) return -1;
	sti();
	while(!ips->pending[0].sin_port) {
		hlt();
	}

	switch(ips->proto)
	{
		case IPPROTO_TCP:
			if(tcp_accept(ips->s.tcp, new_ips->s.tcp, &ips->local, &ips->pending[0])) return -1;
			memset(&ips->pending[0], 0, sizeof(struct sockaddr_in));
			break;
		default:
			return -1;
	}

	return 0;
}

uint64 ip_listen(struct fileh *f, uint64 listen)
{
	struct ip_sock *ips = (struct ip_sock *)f->priv;
	if(ips->state != IPS_SOCKET) return -1;
	ips->state = IPS_LISTEN;
	f->flags |= FS_LISTEN;
	int ret = 0;

	switch(ips->proto)
	{
		case IPPROTO_TCP:
			tcp_listen(ips->s.tcp);
			break;
	}

	if(ret) return ret;
	else return add_listen(f);
}

uint64 ip_bind(struct fileh *f, struct sockaddr_in *sa, uint64 len)
{
	struct ip_sock *ips = (struct ip_sock *)f->priv;
	struct net_dev *dev;

	printf("ip_bind: %x, %x, %x\n", f, sa, len);

	if(len != sizeof(struct sockaddr_in)) return -1;

	dev = find_dev_ip(sa->sin_addr.s_addr);
	f->sdev.net_dev = dev;

	memcpy(&ips->local, sa, len);

	f->flags |= FS_BOUND;

//	printf("ip_bound: bound (dev=%x)\n", f->sdev.net_dev);

	return 0;
}

void ip_init_socket(struct fileh *f, uint64 type, uint64 proto)
{
	struct ip_sock *ip_sock;

	ip_sock = (struct ip_sock *)kmalloc(sizeof (struct ip_sock), "ip_sock", f->task);
	if(!ip_sock) return;

	f->priv = ip_sock;
	ip_sock->f = f;

	switch(type)
	{
		case SOCK_STREAM:
			tcp_init_socket(f);
			break;
		default:
			printf("ip_init_socket: unsupported type: %x\n");
			goto fail;
			break;
	}
	ip_sock->state = IPS_SOCKET;
	return;

fail:
	kfree(ip_sock);
	f->priv = NULL;
}

struct net_dev *find_dev_route(uint32 dst)
{
	struct net_dev *n;

	for( n = netdevs ; n ; n=n->next )
	{
		if(n->state != NET_READY) continue;
		if(n->ip.addr == 0) continue;
		return n;
	}

	return NULL;
}

uint64 ip_send(struct net_dev *nd, uint32 src, uint32 dst, 
		uint8 proto, uint8 *data, uint16 len, uint16 id, uint16 flag)
{
	struct ip_hdr tmp;
	uint8 *snd;
	uint16 hlen = (uint16)sizeof(struct ip_hdr);
	uint16 totlen = hlen + len;

	if(nd == NULL && src != INADDR_ANY) {
		nd = find_dev_ip(src);
	} else if(nd == NULL) {
		nd = find_dev_route(dst);
	}

	if(nd == NULL) {
		printf("ip_send: nd is null: {%x,%x}\n", src, dst);
		return -1;
	}

	if(src == INADDR_ANY) { 
		src = nd->ip.addr;
	}

	/*
	printf("ip_send: {src:%x, dst:%x} l:%x\n", 
			src, dst,
			len);
*/

	memset(&tmp, 0, hlen);

	tmp.version = 4;
	tmp.hlen = 5;
	tmp.len = htons(totlen);
	tmp.id = htons(id);
	tmp.ttl = 64;
	tmp.proto = proto;
	tmp.src = htonl(src);
	tmp.dst = htonl(dst);
	tmp.offset = 0;
	if(flag & IPF_DF) tmp.offset |= IPF_DF;
	tmp.offset = htons(tmp.offset);

	snd = (uint8 *)kmalloc((uint64)totlen, "ip_send", NULL);

	memcpy(snd, 		&tmp, hlen);
	memcpy(snd+hlen, 	data, len);

	((struct ip_hdr *)snd)->checksum = checksum((uint16 *)snd, hlen);

	nd->ops->write(NULL, nd, snd, totlen, NETPROTO_IP);

	kfree(snd);
	return 0;
}

uint64 icmp_recv(struct net_dev *nd, uint32 src, uint32 dst, 
		uint8 *data, uint64 len, struct ip_hdr *iph)
{
	uint8 *icmp_data;
	struct icmp_hdr *hdr = (struct icmp_hdr *)data;
	uint8 *tmp;
	struct icmp_hdr *tmp_h;

	icmp_data = data + sizeof(struct icmp_hdr);

	switch(hdr->type)
	{
		case ICMP_ECHO_REQUEST:
			printf("icmp_recv: ICMP_ECHO_REQUEST: len=%x\n", len);
			tmp = (uint8 *)kmalloc(len, "icmphdr", NULL);

			len -= sizeof(struct icmp_hdr);

			tmp_h = (struct icmp_hdr *)tmp;
			tmp_h->type = ICMP_ECHO_REPLY;
			tmp_h->code = 0;
			tmp_h->check = 0;

			memcpy(tmp+sizeof(struct icmp_hdr), 
					data+sizeof(struct icmp_hdr), len);

			tmp_h->check = checksum((uint16 *)tmp, 
					(uint32)(sizeof(struct icmp_hdr)+len));

			ip_send(nd, dst, src, IPPROTO_ICMP, (uint8 *)tmp, 
					(uint16)(sizeof(struct icmp_hdr)+len), iph->id, IPF_DF);
			kfree(tmp);
			break;
		default:
			printf("icmp_recv: Unknown type: %x\n", hdr->type);
			break;
	}

	return 0;
}

uint64 ip_recv(struct net_dev *nd, struct net_proto *np, 
		uint8 *data, uint64 len)
{
	struct ip_hdr *hdr = (struct ip_hdr *)data;
	uint16 payload;

	hdr->len = ntohs(hdr->len);
	hdr->id = ntohs(hdr->id);
	hdr->offset = ntohs(hdr->offset);
	hdr->checksum = ntohs(hdr->checksum);
	hdr->src = ntohl(hdr->src);
	hdr->dst = ntohl(hdr->dst);

	payload = hdr->len - (hdr->hlen<<2);
	/*

	   printf("ip_recv: {id:%x p:%u off:%u src:%x dst:%x %s%s}, "
	   "len=%u\n",
	   hdr->id, 
	   hdr->proto, 
	   hdr->offset & IPF_OFFSET,
	   hdr->src, 
	   hdr->dst,
	   (hdr->offset & IPF_DF) ? "DF" : "",
	   (hdr->offset & IPF_MF) ? "MF" : "",
	   len
	   );
	   */
	if(hdr->len > len ) {
		printf("ip_recv: bad header len: %x vs %x\n",
				len, hdr->len);
		return -1;
	}

	switch(hdr->proto)
	{
		case IPPROTO_ICMP:
			icmp_recv(nd, hdr->src, hdr->dst, data + (hdr->hlen<<2), 
					payload, hdr);
			break;
		case IPPROTO_TCP:
			tcp_recv(nd, hdr->src, hdr->dst, data + (hdr->hlen<<2),
					payload, hdr);
			//dump_tcbs();
			break;
		default:
			printf("ip_recv: unknown protocol: %x\n", hdr->proto);
			break;
	}

	return 0;
}

struct net_proto_ops ip_proto_ops = {
	ip_init,
	ip_recv
};

uint16 checksum(uint16 *data, uint32 len)
{
	uint32 sum;

	//	printf("checksum: %x[%x]: ", data, len);

	for(sum=0; len>1; len-=2)
		sum += *data++;

	if(len) sum += *(uint8*)data;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	sum = ~sum;

	//	printf("r:%x\n", sum);

	return (uint16)sum;
}
