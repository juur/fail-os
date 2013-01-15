#include "ip.h"
#include "mem.h"
#include "tcp.h"

struct tcb *tcbs = NULL;

const char *tcp_states[TCP_STATES] = {
	"CLOSED",
	"LISTEN",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT_1",
	"FIN_WAIT_2",
	"CLOSING",
	"TIME_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK"
};


void dump_tcbs()
{
	struct tcb *t;

	printf("dump_tcbs: dumping\n");

	for( t = tcbs ; t ; t=t->next )
	{
		printf(" %x:%u -> %x:%u [rx:%lx tx:%lx] %s\n",
				t->src,
				t->src_port,
				t->dst,
				t->dst_port,
				t->rx,
				t->tx,
				(t->state < TCP_STATES) ? tcp_states[t->state] : ""
			  );
	}

	printf("dump_tcbs: done\n");
}

struct tcb *find_tcbs(uint32 src, uint32 dst, uint16 src_port, uint16 dst_port)
{
	struct tcb *t;
	for( t = tcbs ; t ; t=t->next )
	{
		if(t->src == src 
				&& t->dst == dst 
				&& t->src_port == src_port 
				&& t->dst_port == dst_port) 
			return t;
		if(t->src == dst
				&& t->dst == src
				&& t->src_port == dst_port 
				&& t->dst_port == src_port) 
			return t;
	}

	return NULL;
}
/*
   void tcp_rst(uint32 src, uint16 src_port, uint32 dst, uint32 dst_port,
   uint32 seq_num, uint32 ack_num)
   {
   struct tcp_hdr *hdr;
   struct tcp_phdr *phdr;

   phdr = (struct tcp_phdr *)kmalloc(sizeof(struct tcp_phdr), "tcp_phdr");
   phdr->src = htonl(src);
   phdr->dst = htonl(dst);
   phdr->protocol = IPPROTO_TCP;
   hdr = &phdr->hdr;
   hdr->src_port = htons(src_port);
   hdr->dst_port = htons(dst_port);
   hdr->ack_num = htonl(seq_num+1);
   hdr->seq_num = 0;
   hdr->data_offset = 20>>2;
   hdr->rst = 1;
   hdr->ack = 1;
   hdr->window = 0;
   phdr->tcp_length = htons(hdr->data_offset<<2);
   hdr->chksum = checksum((uint16 *)phdr, sizeof(struct tcp_phdr));

   ip_send(NULL, src, dst, IPPROTO_TCP,
   (uint8 *)hdr, sizeof(struct tcp_hdr), 0, 0);
   }
   */
uint64 tcp_listen(struct tcb *tcb)
{
	if(!tcb) return -1;
	tcb->state = LISTEN;
	return 0;
}

uint64 tcp_accept(struct tcb *tcb, struct tcb *new_tcb,
		struct sockaddr_in *src_in, struct sockaddr_in *dst_in)
{
	//struct fileh *f;
	//struct tcp_hdr *hdr;
	//struct tcp_phdr *phdr;
	struct net_dev *nd;
	uint32 src,dst;
	uint64 ret;

	printf("tcp_accept: %x/%x %x %x\n", tcb, new_tcb, src_in, dst_in);

	if(!tcb || !new_tcb) return -1;
	//f = ips->f;

	new_tcb->parent = tcb;
	new_tcb->state = SYN_RECV;
	new_tcb->dst = dst = dst_in->sin_addr.s_addr;
	new_tcb->src_port = src_in->sin_port;
	new_tcb->dst_port = dst_in->sin_port;
	src = src_in->sin_addr.s_addr;

	if(src == INADDR_ANY) {
		nd = find_dev_ip(src);
		if(nd == NULL) {
			nd = find_dev_route(dst);
			if(nd == NULL) {
				printf("tcp_accept: can't find net_dev\n");
				return -1;
			}
		}
		src = nd->ip.addr;
	}

	new_tcb->src = src;

	if(tcb) {
		new_tcb->dst_seq = tcb->dst_seq;
	}

	new_tcb->rx++;

	if(!(ret = tcp_send(new_tcb, NULL, 0, TCP_ACK|TCP_SYN)))
		new_tcb->state = ESTABLISHED;

	return ret;

	/*
	   printf("tcp_accept: local {%x:%u} remote {%x:%u}\n",
	   ips->local.sin_addr.s_addr,
	   ips->local.sin_port,
	   ips->pending[r].sin_addr.s_addr,
	   ips->pending[r].sin_port);
	   */

	/*

	   phdr = (struct tcp_phdr *)kmalloc(sizeof(struct tcp_phdr), "tcp_phdr");

	   phdr->src = htonl(src);
	   phdr->dst = htonl(dst);
	   phdr->protocol = IPPROTO_TCP;

	   hdr = &phdr->hdr;

	   hdr->src_port = htons(ips->local.sin_port);
	   hdr->dst_port = htons(ips->pending[r].sin_port);
	   hdr->data_offset = 20>>2;
	   hdr->ack = 1;
	   hdr->syn = 1;
	   hdr->window = htons(1000);
	   hdr->ack_num = htonl(ips->s.tcp->last_ack = ips->s.tcp->last_seq + 1);
	   hdr->seq_num = htonl(ips->s.tcp->last_seq = 
	   (uint32)((uint64)ips+r+(uint64)hdr+ips+hdr->ack_num));

	   phdr->tcp_length = htons(hdr->data_offset<<2);

	   hdr->chksum = checksum((uint16 *)phdr, sizeof(struct tcp_phdr));

	   ip_send(ips->f->sdev.net_dev, ips->local.sin_addr.s_addr,
	   ips->pending[r].sin_addr.s_addr, IPPROTO_TCP,
	   (uint8 *)hdr, sizeof(struct tcp_hdr), 0, 0);

	   ips->s.tcp->state = ESTABLISHED;

	   kfree(phdr);
	   */
	return 0;
}
/*
   void tcp_syn(struct tcb *tcb, struct tcp_hdr *in_hdr)
   {
   struct tcp_phdr *phdr;
   struct tcp_hdr *hdr;

   printf("tcp_syn: {%x,%x} {%x,%x}\n", 
   in_hdr->seq_num, 
   in_hdr->ack_num,
   tcb->last_seq,
   tcb->last_ack);

//hlt();

phdr = (struct tcp_phdr *)kmalloc(sizeof(struct tcp_phdr), "tcp_phdr");
phdr->src = htonl(tcb->src);
phdr->dst = htonl(tcb->dst);
phdr->protocol = IPPROTO_TCP;
hdr = &phdr->hdr;
hdr->src_port = htons(tcb->src_port);
hdr->dst_port = htons(tcb->dst_port);
hdr->data_offset = 20>>2;
hdr->syn = 1;
hdr->window = htons(1000);
hdr->seq_num = htonl(++tcb->last_seq);
phdr->tcp_length = htons(hdr->data_offset<<2);
hdr->chksum = checksum((uint16 *)phdr, sizeof(struct tcp_phdr));

ip_send(NULL, tcb->src, tcb->dst, IPPROTO_TCP, (uint8 *)hdr, 
sizeof(struct tcp_hdr), 0, 0);

kfree(phdr);
return 0;
}

void tcp_ack(struct tcb *tcb, struct tcp_hdr *in_hdr, uint64 len)
{
struct tcp_phdr *phdr;
struct tcp_hdr *hdr;

printf("tcp_ack: {%x,%x} -> {%x,%x}\n",
in_hdr->seq_num, 
in_hdr->ack_num,
tcb->last_seq,
tcb->last_ack);

phdr = (struct tcp_phdr *)kmalloc(sizeof(struct tcp_phdr), "tcp_phdr");
phdr->src = htonl(tcb->src);
phdr->dst = htonl(tcb->dst);
phdr->protocol = IPPROTO_TCP;
hdr = &phdr->hdr;
hdr->src_port = htons(tcb->src_port);
hdr->dst_port = htons(tcb->dst_port);
hdr->data_offset = 20>>2;
hdr->ack = 1;
hdr->window = htons(1000);
hdr->ack_num = htonl(tcb->last_ack = tcb->last_seq = 
in_hdr->seq_num + (len - in_hdr->data_offset<<2) + 1);
phdr->tcp_length = htons(hdr->data_offset<<2);
hdr->chksum = checksum((uint16 *)phdr, sizeof(struct tcp_phdr));

ip_send(NULL, tcb->src, tcb->dst, IPPROTO_TCP, (uint8 *)hdr, 
sizeof(struct tcp_hdr), 0, 0);

kfree(phdr);
return 0;
}
*/
uint64 tcp_send(struct tcb *tcb, uint8 *data, uint64 len, uint64 flags)
{
	struct tcp_phdr *phdr;
	struct tcp_hdr *hdr;

	phdr = (struct tcp_phdr *)kmalloc(sizeof(struct tcp_phdr) + len, "tcp_send", tcb->sock->task);

	if(!phdr) {
		printf("tcp_send: unable to allocate memory\n");
		return -1;
	}

	hdr = &phdr->hdr;

	if(len && data) memcpy(phdr + TCP_PHDR, data, len);

	phdr->src = htonl(tcb->src);
	phdr->dst = htonl(tcb->dst);
	phdr->protocol = IPPROTO_TCP;

	hdr->src_port = htons(tcb->src_port);
	hdr->dst_port = htons(tcb->dst_port);
	hdr->data_offset = 20>>2;

	if(flags & TCP_ACK) hdr->ack = 1;
	if(flags & TCP_SYN) hdr->syn = 1;
	if(flags & TCP_RST) hdr->rst = 1;
	if(flags & TCP_FIN) hdr->fin = 1;

	hdr->window = htons(tcb->window);

	if(hdr->ack) {
		hdr->ack_num = htonl(tcb->dst_ack = (uint32)(tcb->rx + tcb->dst_seq));
	}

	if(hdr->syn) {
		tcb->src_seq = 1;
		hdr->seq_num = htonl(1);
	} else if(len && data) {
		tcb->tx += len;
		hdr->seq_num = htonl(tcb->src_seq + tcb->tx);
	} else {
		hdr->seq_num = htonl(tcb->dst_seq + tcb->rx);
	}

	phdr->tcp_length = htons((hdr->data_offset + len) << 2);
	hdr->chksum = checksum((uint16 *)phdr, sizeof(struct tcp_phdr) + len);

	printf("tcp_send: %x:%u -> %x:%u seq:%x ack:%x %s%s%s%s\n",
			tcb->src, tcb->src_port, tcb->dst, tcb->dst_port,
			ntohl(hdr->seq_num),
			ntohl(hdr->ack_num),
			(hdr->ack ? "ACK ": ""),
			(hdr->syn ? "SYN ": ""),
			(hdr->fin ? "FIN ": ""),
			(hdr->rst ? "RST ": "")
		  );

	ip_send(NULL, tcb->src, tcb->dst, IPPROTO_TCP, (uint8 *)hdr,
			TCP_HDR + len, 0, 0);

	kfree(phdr);

	return 0;
}

void tcp_init_socket(struct fileh *f)
{
	struct ip_sock *ips = (struct ip_sock *)f->priv;

	ips->proto = IPPROTO_TCP;

	if(ips->s.tcp == NULL) {
		ips->s.tcp = (struct tcb *)kmalloc(sizeof(struct tcb), "tcb", f->task);
		ips->s.tcp->next = tcbs;
		tcbs = ips->s.tcp;
	}

	ips->s.tcp->state = CLOSED;
	ips->s.tcp->window = 1000;

}


uint64 tcp_recv(struct net_dev *nd, uint32 src, uint32 dst,
		uint8 *data, uint64 len, struct ip_hdr *iph)
{
	uint8 *tcp_data;
	struct tcp_hdr *hdr = (struct tcp_hdr *)data;
	struct fileh *listen;
	struct sockaddr_in sin;
	struct ip_sock *ips;
	struct tcb *tcb;
	uint64 hdr_len = hdr->data_offset << 2;

	tcp_data = data + hdr_len;

	hdr->src_port = ntohs(hdr->src_port);
	hdr->dst_port = ntohs(hdr->dst_port);
	hdr->seq_num = ntohl(hdr->seq_num);
	hdr->ack_num = ntohl(hdr->ack_num);

	printf("tcp_recv: %x:%u -> %x:%u %s%s%s%s seq:%x ack:%x\n",
			src,
			hdr->src_port,
			dst,
			hdr->dst_port,
			hdr->syn ? "SYN " : "",
			hdr->ack ? "ACK " : "",
			hdr->rst ? "RST " : "",
			hdr->fin ? "FIN " : "",
			hdr->seq_num,
			hdr->ack_num
		  );

	tcb = find_tcbs(iph->src, iph->dst, hdr->src_port, hdr->dst_port);
	if(!tcb) {
		printf("tcp_recv: no tcb\n");
		if(hdr->syn && !hdr->ack) {
			printf("tcp_recv: SYN\n");

			sin.sin_port = hdr->dst_port;
			sin.sin_addr.s_addr = iph->dst;
			listen = find_listen(AF_INET, (struct sockaddr *)&sin, IPPROTO_TCP);

			if(!listen) {
				sin.sin_addr.s_addr = INADDR_ANY;
				listen = find_listen(AF_INET, (struct sockaddr *)&sin, IPPROTO_TCP);
				if(!listen) {
					tcp_send(tcb, NULL, 0, TCP_RST);
					printf("tcp_recv: SYN: can't find a listen\n");
					return -1;
				}
			}
			ips = (struct ip_sock *)listen->priv;
			if(!ips || ips->pending[0].sin_family) {
				printf("tcp_recv: SYN: listen full\n");
				tcp_send(tcb, NULL, 0, TCP_RST);
				return -1;
			}
			/*
			   tcb = ips->s.tcp;
			   tcb->src = iph->dst;
			   tcb->dst = iph->src;
			   tcb->src_port = hdr->dst_port;
			   tcb->dst_port = hdr->src_port;
			   tcb->sock = listen;
			   */

			tcb = ips->s.tcp;
			tcb->dst_seq = hdr->seq_num;
			 
			ips->pending[0].sin_family = AF_INET;
			ips->pending[0].sin_port = hdr->src_port;
			ips->pending[0].sin_addr.s_addr = iph->src;

			return 0;
		} else {
			/*
			   tcp_rst(iph->dst, hdr->dst_port, iph->src,
			   hdr->src_port, hdr->seq_num, hdr->ack_num);
			   */
			return -1;
		}
	} else {
		/*
		printf("tcp_recv: tcb {%x:%u -> %x:%u}\n",
				tcb->src, tcb->src_port,
				tcb->dst, tcb->dst_port);
				*/
	}

	switch(tcb->state)
	{
		case ESTABLISHED:
			//tcp_ack(tcb, hdr, len);
			printf("tcp_recv: hdr=%u tot=%u diff=%u\n", hdr_len, len, 
					hdr->seq_num - tcb->dst_seq);
			if(len - hdr_len) {
				tcb->rx += len - hdr_len;
				tcp_send(tcb, NULL, 0, TCP_ACK);
			} if(hdr->seq_num > tcb->dst_seq + tcb->rx) {
				tcb->rx += hdr->seq_num - tcb->dst_seq;
				tcp_send(tcb, NULL, 0, TCP_ACK|(hdr->fin ? TCP_FIN : 0));
			}
			break;
		default:
			printf("tcp_recv: unhandled state: %s\n", tcp_states[tcb->state]);
	}

	if(hdr->rst) {
	} else if(hdr->fin) {
		/*
		   tcp_rst(iph->dst, hdr->dst_port, iph->src,
		   hdr->src_port, hdr->seq_num, hdr->ack_num);
		   */
		// find tcb!!!
		// tcb->state = FIN_WAIT_2;
	}

	return 0;
}

