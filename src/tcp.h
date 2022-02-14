#ifndef _TCP_H
#define _TCP_H

#include "ip.h"

struct tcp_hdr {
	uint16_t  src_port;
	uint16_t  dst_port;
	uint32_t  seq_num;
	uint32_t  ack_num;

	unsigned    res:3;
	unsigned    ns:1;
	unsigned    data_offset:4;

	unsigned    fin:1;
	unsigned    syn:1;
	unsigned    rst:1;
	unsigned    psh:1;
	unsigned    ack:1;
	unsigned    urg:1;
	unsigned    ece:1;
	unsigned    cwr:1;

	uint16_t  window;
	uint16_t  chksum;
	uint16_t  urg_ptr;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
;

struct tcp_phdr {
	uint32_t  src;
	uint32_t  dst;
	uint8_t   res;
	uint8_t   protocol;
	uint16_t  tcp_length;
	struct  tcp_hdr hdr;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
;

#define TCP_FIN	0x01
#define	TCP_SYN	0x02
#define	TCP_RST	0x04
#define	TCP_PSH	0x08
#define	TCP_ACK	0x10
#define	TCP_URG	0x20

#define TCP_HDR 	sizeof(struct tcp_hdr)
#define TCP_PHDR	sizeof(struct tcp_phdr)

#define CLOSED		0
#define LISTEN		1
#define SYN_SENT	2
#define SYN_RECV	3
#define ESTABLISHED	4
#define FIN_WAIT_1	5
#define FIN_WAIT_2	6
#define CLOSING		7
#define TIME_WAIT	8
#define CLOSE_WAIT	9
#define LAST_ACK	10
#define TCP_STATES	11

extern const char *tcp_states[TCP_STATES];

struct tcp_buf {
	struct tcp_buf	*next;
	struct tcp_buf	*prev;
	struct tcp_hdr	hdr;
};

struct tcb {
	struct tcb 		*next;
	struct fileh	*sock;
	struct tcp_buf	*recv_q;
	struct tcp_buf	*send_q;
	struct tcb		*parent;

	uint64_t tx;		// bytes we've sent
	uint64_t rx;		// bytes they've sent

	uint32_t src_seq; // our initial seq
	uint32_t dst_seq; // their initial seq

	uint32_t src_ack; // their ack of us
	uint32_t dst_ack;	// our ack of them

	uint32_t src;		// our IP
	uint32_t dst;		// their IP

	uint32_t state;
	uint16_t src_port;	// our port
	uint16_t dst_port;	// their port

	uint16_t window;
};

void dump_tcbs(void);
uint64_t tcp_accept(struct tcb *tcb, struct tcb *new_tcb,
		        struct sockaddr_in *src_in, struct sockaddr_in *dst_in);
uint64_t tcp_listen(struct tcb *tcb);
void tcp_init_socket(struct fileh *f);
uint64_t tcp_recv(struct net_dev *nd, uint32_t src, uint32_t dst, int8_t *data, 
		uint64_t len, struct ip_hdr *iph);
uint64_t tcp_send(struct tcb *tcb, int8_t *data, uint64_t len, uint64_t flags);

#endif
