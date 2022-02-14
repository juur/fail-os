#include "net.h"
#include "dev.h"
#include "mem.h"
#include "ppp.h"

extern bool memdebug;

uint8_t ppp_byte(struct char_dev *cd);

uint64_t ppp_init(struct net_dev *nd, void *phys, int type, struct net_proto *up)
{
	struct char_dev *cd;
	struct ppp_private *priv; 

	if( type != DEV_CHAR ) return -1;

	cd = (struct char_dev *)phys;

	priv = (struct ppp_private *)kmalloc(sizeof(struct ppp_private), "ppp_private", NULL);
	nd->priv = priv;

	priv->hw = cd;

	return 0;
}

uint64_t ppp_wbyte(struct char_dev *cd, unsigned char byte)
{
	//	char esc = HDLC_ESCAPE;

	//	printf("%x ", byte);

	//	if(byte < 0x20) {
	//		cd->ops->write(cd, &esc, 1);
	//		byte += 0x20;
	//	}
	cd->ops->write(cd, (char *)&byte, 1);

	return 0;
}

uint64_t lcp_init_reply(uint8_t *buf, uint8_t code, uint8_t id, uint8_t *cnt,
		uint16_t *len, uint16_t proto)
{
	buf[0] = HDLC_PPP_ADDR;
	buf[1] = HDLC_PPP_CMD;
	buf[2] = (proto>>8)&0xff;
	buf[3] = proto&0xff;
	buf[4] = code;
	buf[5] = id;

	*cnt = 0;
	*len = 8; 


	return 0;
}

uint64_t lcp_add(uint8_t *buf, uint8_t *cnt, uint16_t *len, uint8_t ptype, uint8_t plen, 
		uint8_t *pdata)
{
	int i;

	buf[(*len)++] = ptype;
	buf[(*len)++] = plen+2;

	for(i=0;i<plen;i++)
	{
		buf[(*len)++] = pdata[i];
	}

	(*cnt)++;

	return 0;
}

uint64_t lcp_close(uint8_t *buf, uint8_t *cnt, uint16_t *len)
{
	buf[6] = (((*len)-4) >> 8) & 0xff;
	buf[7] = ((*len)-4) & 0xff;

	return 0;
}

uint64_t send_lcp(struct char_dev *cd, uint8_t *buf, uint16_t len)
{
	//uint8_t term = HDLC_FLAG;

	printf("send_lcp: %x%x %x %x %x%x\n", 
			buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

	int i;

	for(i=0;i<len;i++)
	{
		ppp_wbyte(cd,buf[i]);
	}
	// cd->ops->write(cd, (char *)&term, 1);

	return len;
}

uint64_t process_lcp(uint16_t proto, struct net_dev *nd, struct char_dev *cd)
{
	uint8_t	code, id;
	uint16_t	len, seek;
	uint8_t	*parms, *tmp;
	uint8_t	ptype, plen;
	uint32_t	data32;
	uint8_t	lcp_cnt = 0;
	uint16_t	lcp_len = 0;
	uint8_t	*ret;
	int		i;
	static bool fail = false, fail2 = false;

	code = ppp_byte(cd);
	id = ppp_byte(cd);
	len = ppp_byte(cd) << 8;
	len |= ppp_byte(cd);

	printf("process_lcp: proto:%x code:%x id:%x len:%x\n", 
			proto, code, id, len);

	len -= 4;
	seek = len;

	parms = (uint8_t *)kmalloc((uint64_t)len, "lcp.parms", NULL);
	tmp = parms;
	ret = (uint8_t *)kmalloc((uint64_t)len, "lcp.ret", NULL);

	for(i=0;i<len;i++)
	{
		tmp[0] = ppp_byte(cd);
		tmp++;
	}

	lcp_init_reply(ret, (uint8_t)LCP_CONF_ACK, id, &lcp_cnt, &lcp_len, proto);
	switch(code)
	{
		case LCP_CONF_REQ:
			seek = 0;
			printf("process_lcp: LPC_CONF_REQ:\n");
			while(seek < len)
			{
				ptype = parms[seek++];
				plen = parms[seek++];
				printf(" t:%x l:%x seek:%x/%x ", ptype, plen, seek, len);
				switch(proto)
				{
					case PID_LCP:
						printf("LCP ");
						switch(ptype)
						{
							case LCPC_MAGIC_NUMBER:
								printf("magic: ");
								data32 = 0;
								for(i=0;i<=3;i++) {
									data32 |= (uint32_t)parms[seek++] << (i*8);
								}
								printf("magic: %x ", data32);
								lcp_add(ret, &lcp_cnt, &lcp_len, ptype, 4, 
										(uint8_t *)&data32);
								break;
							case LCPC_ASYNCMAP:
								data32 = 0;
								for(i=0;i<=3;i++) {
									data32 |= (uint32_t)parms[seek++] << (i*8);
								}
								printf("asyncmap: %x ", data32);
								lcp_add(ret, &lcp_cnt, &lcp_len, ptype, 4,
										(uint8_t *)&data32);
								break;
							default:
								seek += (plen-2);
								printf("unknown LCP: %x", ptype);
								break;
						}
						break;
					case PID_IPCP:
						printf("IPCP ");
						switch(ptype)
						{
							case IPCPC_IPADDR:
								data32 = 0;
								for(i=0;i<=3;i++) {
									data32 |= (uint32_t)parms[seek++] << (i*8);
								}
								printf("ip: %x ", data32);
								lcp_add(ret, &lcp_cnt, &lcp_len, ptype, 4,
										(uint8_t *)&data32);
								break;
							default:
								seek += (plen-2);
								printf("unknown IPCP: %x", ptype);
								break;
						}
						printf("\n");
				}
			}
			lcp_close(ret, &lcp_cnt, &lcp_len);
			send_lcp(cd, ret, lcp_len);
			break;
		case LCP_CONF_ACK:
			printf("process_lcp: LCP_CONF_ACK\n");
			break;
		default:
			printf("lcp: UNKNOWN: %x\n", code);
			break;
	}

	kfree(parms);
	kfree(ret);

	lcp_cnt = lcp_len = data32 = 0;

	if(proto == PID_LCP && !fail) {
		fail = true;
		ret = (uint8_t *)kmalloc(100, "lcp.init", NULL);
		lcp_init_reply(ret, LCP_CONF_REQ, 10, &lcp_cnt, &lcp_len, proto);
		lcp_add(ret, &lcp_cnt, &lcp_len, LCPC_ASYNCMAP, 4, (uint8_t *)&data32);
		lcp_close(ret, &lcp_cnt, &lcp_len);
		send_lcp(cd, ret, lcp_len);
		kfree(ret);
	} else if(proto == PID_IPCP && !fail2) {
		fail2 = true;
		ret = (uint8_t *)kmalloc(100, "ipcp.init", NULL);
		lcp_init_reply(ret, LCP_CONF_REQ, 10, &lcp_cnt, &lcp_len, proto);
		lcp_add(ret, &lcp_cnt, &lcp_len, IPCPC_IPADDR, 4, (uint8_t *)&data32);
		lcp_close(ret, &lcp_cnt, &lcp_len);
		send_lcp(cd, ret, lcp_len);
		kfree(ret);
	}


	return 0;
}

uint64_t ppp_process(struct net_dev *nd)
{
	struct ppp_private *priv;
	struct char_dev *cd;
	uint8_t byte;
	uint16_t proto;

	priv = (struct ppp_private *)nd->priv;
	cd = priv->hw;


	if(cd->ops->pending(cd)<4) return 0;

	//	do {
	//		byte = ppp_byte(cd);
	//		if(!cd->ops->pending(cd)) return 0;
	//	} while(byte != (uint8_t)HDLC_FLAG);
	byte = ppp_byte(cd);
	if(byte != (uint8_t)HDLC_PPP_ADDR) printf("ppp_process: HDLC_PPP_ADDR\n");
	byte = ppp_byte(cd);
	if(byte != (uint8_t)HDLC_PPP_CMD) printf("ppp_process: HDLC_PPP_CMD\n");
	byte = ppp_byte(cd);
	if(!(byte & 0x1)) {
		proto = byte << 8;
		proto |= ppp_byte(cd);
	} else {
		proto = byte;
	}

	switch(proto) 
	{
		case PID_LCP:
			process_lcp(PID_LCP, nd, cd);
			break;
		case PID_IPCP:
			process_lcp(PID_IPCP, nd, cd);
			break;
		default:
			printf("ppp_process: unknown protocol: %x\n", proto);
			break;
	}

	/*
	   ppp_byte(cd); // fcs
	   ppp_byte(cd); // fcs
	   ppp_byte(cd); // last
	   */

	return 0;
}

uint8_t ppp_byte(struct char_dev *cd)
{
	uint8_t byte;

	cd->ops->read(cd, (char *)&byte, 1);

	//	if(byte == HDLC_ESCAPE) {
	//		cd->ops->read(cd, (char *)&byte, 1);
	//		byte -= 0x20;
	//	}

	//	printf("%x ", byte);

	return byte;
}

uint64_t ppp_read(struct fileh *fh, struct net_dev *nd, unsigned char *dst, uint64_t len, 
		uint64_t wut)
{
	return 0;
}

uint64_t ppp_write(struct fileh *fh, struct net_dev *nd, char *src, uint64_t len, 
		uint32_t wut)
{
	return 0;
}

uint64_t ppp_init_sock(struct fileh *fh, struct net_dev *nd)
{
	return 0;
}

struct net_ops ppp_net_ops = {
	"ppp",
	ppp_write,
	ppp_init,
	ppp_init_sock,
	ppp_process
};


