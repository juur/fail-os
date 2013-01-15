#ifndef _IP_H
#define _IP_H

#include "net.h"

struct ip_hdr {
	unsigned hlen:4;
	unsigned version:4;
	uint8 tos;
	uint16 len;
	uint16 id;
	uint16 offset;
	uint8 ttl;
	uint8 proto;
	uint16 checksum;
	uint32 src;
	uint32 dst;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
;

#define ICMP_ECHO_REPLY	0
#define	ICMP_ECHO_REQUEST	8

struct icmp_hdr {
	uint8 type;
	uint8 code;
	uint16 check;
} 
#ifdef __GNUC__
	__attribute__((packed))
#endif
;

#define	IPF_RF		0x8000
#define	IPF_DF		0x4000
#define	IPF_MF		0x2000
#define	IPF_OFFSET	0x1fff

extern struct net_proto_ops	ip_proto_ops;

#define	IPPROTO_ICMP	1
#define	IPPROTO_TCP		6

#define SOCK_STREAM		1

#define	AF_INET			2

struct in_addr {
	uint32 s_addr;
};

#define INADDR_ANY	((uint32)0x0)

struct sockaddr_in {
	uint16 	sin_family;
	uint16	sin_port;
	struct in_addr sin_addr;
};
/*
struct tcp_state {
	uint64	state;
	uint32	last_seq;
	uint32	last_ack;
};

*/

struct ip_sock;

#include "tcp.h"

struct ip_sock {
	struct fileh *f;
	uint64 proto;
	uint64 state;
	struct sockaddr_in local;
	struct sockaddr_in remote;
	struct sockaddr_in pending[1];
	union {
		struct tcb *tcp;
		uint64 udp;
		uint64 icmp;
	} s;
};

#define IPS_UNDEF		0x0
#define IPS_SOCKET		0x1
#define IPS_LISTEN		0x2
#define IPS_CONNECT		0x3

uint16 checksum(uint16 *data, uint32 len);
uint64 ip_send(struct net_dev *nd, uint32 src, uint32 dst, uint8 proto, uint8 *data, uint16 len, uint16 id, uint16 flag);
struct net_dev *find_dev_route(uint32 dst);
struct fileh *find_listen_ip(struct sockaddr_in *sin, uint32 proto);
uint64 ip_accept(struct fileh *f, struct fileh *newf, struct sockaddr_in *sin, uint64 *len);
uint64 ip_listen(struct fileh *f, uint64 listen);
uint64 ip_bind(struct fileh *f, struct sockaddr_in *sa, uint64 len);
void ip_init_socket(struct fileh *f, uint64 type, uint64 proto);

#endif
