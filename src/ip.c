#include "ip.h"
#include "mem.h"
#include "net.h"

struct fileh *listen = NULL;

struct ip4_route {
	struct ip4_route *next;
	uint32_t dst;
	uint32_t mask;
	uint32_t gw;
	uint32_t weight;
	struct net_dev *dev;
};

struct ip4_route *ip4_table;



uint64_t ip_init(struct net_proto *np)
{
	listen = NULL;
	ip4_table = NULL;
	return 0;
}

struct fileh *find_listen_ip(struct sockaddr_in *sin, uint32_t proto)
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

void dump_listen(void)
{
	struct fileh *f;
	struct ip_sock *ips;

	for( f = listen ; f ; f=f->listen_next )
	{
		if(f->family != AF_INET) continue;
		ips = (struct ip_sock *)f->priv;
		printf("dump_listen: p:%lx local={%u,%u,%u} state=%lx\n",
				ips->proto,
				ips->local.sin_family,
				ips->local.sin_port,
				ips->local.sin_addr.s_addr,
				ips->state);
	}
}

uint64_t add_listen(struct fileh *f)
{
	f->listen_next = listen;
	listen = f;
	dump_listen();
	return 0;
}

int ip_accept(struct fileh *f, struct fileh *newf, struct sockaddr_in *sin, socklen_t *len)
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

int ip_listen(struct fileh *f, int32_t listen)
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

int ip_bind(struct fileh *f, struct sockaddr_in *sa, socklen_t len)
{
	struct ip_sock *ips = (struct ip_sock *)f->priv;
	struct net_dev *dev;

	printf("ip_bind: %p, %p, %x\n", (void *)f, (void *)sa, len);

	if(len != sizeof(struct sockaddr_in)) return -1;

	dev = find_dev_ip(sa->sin_addr.s_addr);
	f->sdev.net_dev = dev;

	memcpy(&ips->local, sa, len);

	f->flags |= FS_BOUND;

	//	printf("ip_bound: bound (dev=%x)\n", f->sdev.net_dev);

	return 0;
}

void ip_init_socket(struct fileh *f, int32_t type, int32_t proto)
{
	struct ip_sock *ip_sock;

	ip_sock = (struct ip_sock *)kmalloc(sizeof (struct ip_sock), "ip_sock", f->task, 0);
	if(!ip_sock) return;

	f->priv = ip_sock;
	ip_sock->f = f;

	switch(type)
	{
		case SOCK_STREAM:
			tcp_init_socket(f);
			break;
		default:
			printf("ip_init_socket: unsupported type: %x\n", type);
			goto fail;
			break;
	}
	ip_sock->state = IPS_SOCKET;
	return;

fail:
	kfree(ip_sock);
	f->priv = NULL;
}

struct net_dev *find_dev_route(uint32_t dst)
{
	// struct net_dev *n;
	struct ip4_route *r;

	for( r = ip4_table ; r ; r=r->next )
	{
		if((dst & r->mask) == r->dst) break;
	}

	// handle sending to IPs on host here / add them to the table

	if( r == NULL ) return NULL;

	if( r->dev ) return(r->dev);

	return find_dev_route(r->gw);
}

uint64_t ip_send(struct net_dev *nd, uint32_t src, uint32_t dst, 
		uint8_t proto, char *data, uint16_t len, uint16_t id, uint16_t flag)
{
	struct ip_hdr tmp;
	char *snd;
	uint16_t hlen = (uint16_t)sizeof(struct ip_hdr);
	uint16_t totlen = hlen + len;

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

	snd = (char *)kmalloc((uint64_t)totlen, "ip_send", NULL, 0);

	memcpy(snd, 		&tmp, hlen);
	memcpy(snd+hlen, 	data, len);

	((struct ip_hdr *)snd)->checksum = checksum((uint16_t *)snd, hlen);

	nd->ops->write(NULL, nd, snd, totlen, NETPROTO_IP);

	kfree(snd);
	return 0;
}

uint64_t icmp_recv(struct net_dev *nd, uint32_t src, uint32_t dst, 
		char *data, uint64_t len, struct ip_hdr *iph)
{
	//void *icmp_data;
	struct icmp_hdr *hdr = (struct icmp_hdr *)data;
	char *tmp;
	struct icmp_hdr *tmp_h;

	//icmp_data = data + sizeof(struct icmp_hdr);

	switch(hdr->type)
	{
		case ICMP_ECHO_REQUEST:
			printf("icmp_recv: ICMP_ECHO_REQUEST: len=%lx\n", len);
			tmp = (char *)kmalloc(len, "icmphdr", NULL, 0);

			len -= sizeof(struct icmp_hdr);

			tmp_h = (struct icmp_hdr *)tmp;
			tmp_h->type = ICMP_ECHO_REPLY;
			tmp_h->code = 0;
			tmp_h->check = 0;

			memcpy(tmp+sizeof(struct icmp_hdr), 
					data+sizeof(struct icmp_hdr), len);

			tmp_h->check = checksum((uint16_t *)tmp, 
					(uint32_t)(sizeof(struct icmp_hdr)+len));

			ip_send(nd, dst, src, IPPROTO_ICMP, tmp, 
					(uint16_t)(sizeof(struct icmp_hdr)+len), iph->id, IPF_DF);
			kfree(tmp);
			break;
		default:
			printf("icmp_recv: Unknown type: %x\n", hdr->type);
			break;
	}

	return 0;
}

uint64_t ip_recv(struct net_dev *nd, struct net_proto *np, 
		char *data, uint64_t len)
{
	struct ip_hdr *hdr = (struct ip_hdr *)data;
	uint16_t payload;

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
		printf("ip_recv: bad header len: %lx vs %x\n",
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

uint64_t ip_ioctl(struct fileh *f, int cmd, void *arg)
{
	struct dev *d;
	struct ifreq *req;
	struct net_dev *nd;

	if(arg == NULL) return -1;
	req = (struct ifreq *)arg;
	d = find_dev_name(req->name, DEV_NULL);
	if(d == NULL) return -1;

	// check missing
	nd = d->op.net_dev;

	switch(cmd)
	{
		case IOC_GIFADDR:
			return (uint64_t)nd->ip.addr;
			break;
		case IOC_SIFADDR:
			nd->ip.addr = req->r.addr.sin_addr.s_addr;
			printf("ip_ioctl: %s IFADDR=%x\n", &d->name[0], nd->ip.addr);
			break;
		case IOC_GIFNETMASK:
			return (uint64_t)nd->ip.netmask;
			break;
		case IOC_SIFNETMASK:
			nd->ip.netmask = req->r.netmask.sin_addr.s_addr;
			printf("ip_ioctl: %s NETMASK=%x\n", &d->name[0], nd->ip.netmask);
			break;
		default:
			printf("ip_ioctl: undefined %x\n", cmd);
			return -1;
	}
	return 0;
}

struct net_proto_ops ip_proto_ops = {
	"ipv4",
	ip_init,
	ip_recv,
	ip_ioctl
};

uint16_t checksum(uint16_t *data, uint32_t len)
{
	uint32_t sum;

	//	printf("checksum: %x[%x]: ", data, len);

	for(sum=0; len>1; len-=2)
		sum += *data++;

	if(len) sum += *(uint8_t*)data;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	sum = ~sum;

	//	printf("r:%x\n", sum);

	return (uint16_t)sum;
}
