#ifndef _PPP_H
#define _PPP_H

struct hdlc_ppp_hdr {
	uint8	flag;
	uint8	addr;
	uint8	cont;
};

#define HDLC_FLAG		0x7e
#define HDLC_PPP_ADDR	0xff
#define	HDLC_PPP_CMD	0x03
#define HDLC_ESCAPE		0x7d

#define PID_LCP			0xc021
#define PID_IPCP		0x8021

#define	LCP_CONF_REQ		0x01
#define	LCP_CONF_ACK		0x02
#define	LCP_CONF_NAK		0x03
#define	LCP_CONF_REJ		0x04
#define	LCP_TERM_REQ		0x05
#define	LCP_TERM_ACK		0x06

#define LCPC_ASYNCMAP		0x02
#define	LCPC_MAGIC_NUMBER	0x05

#define IPCPC_IPADDR		0x03

struct ppp_private {
	struct char_dev *hw;
};

extern struct net_ops ppp_net_ops;

#endif
