#ifndef _IP_H
#define _IP_H

#include <net.h>
#include <dev.h>

struct ip_hdr {
	unsigned hlen:4;
	unsigned version:4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t offset;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	uint32_t src;
	uint32_t dst;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
;

#define ICMP_ECHO_REPLY		0
#define	ICMP_ECHO_REQUEST	8

struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t check;
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

#define	IPPROTO_ICMP	0x01
#define	IPPROTO_TCP		0x06
#define IPPROTO_UDP		0x11

struct in_addr {
	uint32_t s_addr;
};

#define INADDR_ANY	((uint32_t)0x0)

struct sockaddr_in {
	uint16_t 	sin_family;
	uint16_t	sin_port;
	struct in_addr sin_addr;
};
/*
struct tcp_state {
	uint64_t	state;
	uint32_t	last_seq;
	uint32_t	last_ack;
};

*/

struct ip_sock;

#include <tcp.h>
#include <udp.h>

struct ip_sock {
	struct fileh *f;
	uint64_t proto;
	uint64_t state;
	struct sockaddr_in local;
	struct sockaddr_in remote;
	struct sockaddr_in pending[1];
	union {
		struct tcb *tcp;
		uint64_t udp;
		uint64_t icmp;
	} s;
};

#define IOC_GIFADDR	0x1000
#define IOC_SIFADDR	0x1001
#define IOC_GIFNETMASK	0x1002
#define IOC_SIFNETMASK	0x1003

struct ifreq {
	char name[DEVNAME];
	union {
		struct sockaddr_in addr;
		struct sockaddr_in netmask;
	} r;
};

#define IPS_UNDEF		0x0
#define IPS_SOCKET		0x1
#define IPS_LISTEN		0x2
#define IPS_CONNECT		0x3

extern uint16_t ipv4_checksum(uint16_t *data, uint32_t len);
extern uint64_t ip_send(struct net_dev *nd, uint32_t src, uint32_t dst, uint8_t proto, int8_t *data, uint16_t len, uint16_t id, uint16_t flag);
extern int ip_accept(struct fileh *f, struct fileh *newf, struct sockaddr_in *sin, socklen_t *len);
extern int ip_listen(struct fileh *f, int32_t listen);
extern int ip_bind(struct fileh *f, struct sockaddr_in *sa, socklen_t len);
extern struct net_dev *find_dev_route(uint32_t dst);
extern struct fileh *find_listen_ip(struct sockaddr_in *sin, uint32_t proto);
extern int ip_init_socket(struct fileh *f, int type, int proto);

#endif
