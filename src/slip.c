#include "slip.h"
#include "dev.h"
#include "mem.h"

#define SLIP_MAX_PACKET	1006
#define	SLIP_END		0300
#define	SLIP_ESC		0333
#define	SLIP_ESC_END	0334
#define	SLIP_ESC_ESC	0335


uint64 slip_send_packet(uint8 *p, uint64 len, struct char_dev *cd)
{
	uint8 tmp;

	//printf("slip_send: %x l:%x\n", p, len);

	if( len > SLIP_MAX_PACKET ) len = SLIP_MAX_PACKET;

	tmp = SLIP_END; cd->ops->write(cd, &tmp, 1);


	while(len--)
	{
	//	printf("%x ", *p);
		switch(*p)
		{
			case SLIP_END:
				tmp = SLIP_ESC; cd->ops->write(cd, &tmp, 1);
				tmp = SLIP_ESC_END; cd->ops->write(cd, &tmp, 1);
				break;
			case SLIP_ESC:
				tmp = SLIP_ESC; cd->ops->write(cd, &tmp, 1);
				tmp = SLIP_ESC_ESC; cd->ops->write(cd, &tmp, 1);
				break;
			default:
				cd->ops->write(cd, p, 1);
				break;
		}
		p++;
	}
	tmp = SLIP_END; cd->ops->write(cd, &tmp, 1);

	//printf("\n");

	return len;
}

uint64 slip_recv_packet(uint8 *p, uint64 len, struct char_dev *cd)
{
	uint64 received = 0;
	uint8 byte;

	while(1)
	{
		cd->ops->read(cd, &byte, 1);
		switch(byte)
		{
			case SLIP_END:
				if(received) { 
				//	printf("\n");
					return received;
				}
				else break;
			case SLIP_ESC:
				cd->ops->read(cd, &byte, 1);
				switch(byte)
				{
					case SLIP_ESC_END:
						byte = SLIP_END;
						break;
					case SLIP_ESC_ESC:
						byte = SLIP_ESC;
						break;
				}
			default:
				if(received < len) {
					p[received++] = byte;
				//	printf("%x ", byte);
				}
		}
	}
}

uint64 slip_init(struct net_dev *nd, void *phys, int type, 
		struct net_proto *np)
{
	struct char_dev *cd;
	struct slip_private *priv;
	
	printf("slip_init: ");

	if( type != DEV_CHAR ) return -1;

	cd = (struct char_dev *)phys;

	priv = (struct slip_private *)kmalloc(sizeof(struct slip_private), "slip_private", NULL);
	nd->priv = priv;

	priv->hw = cd;

	printf("done\n");

	return 0;
}

uint64 slip_process(struct net_dev *nd)
{
	struct slip_private *priv;
	struct char_dev *cd;
	struct char_ops *ops;
	uint8 *packet;
	uint64 len;

	priv = (struct slip_private *)nd->priv;
	cd = priv->hw;
	ops = cd->ops;

	if(!ops->pending(cd)) return 0;

//	printf("slip_process\n");

	packet = (uint8 *)kmalloc(SLIP_MAX_PACKET, "slippacket", NULL);
	if(!packet) return -1;

	len = slip_recv_packet(packet, SLIP_MAX_PACKET, cd);

//	printf("slip_process: got %x bytes\n", len);

	nd->upper->ops->recv(nd, nd->upper, packet, len);

	kfree(packet);
//	printf("kfree2done");
	return 0;
}

uint64 slip_write(struct fileh *fh, struct net_dev *nd, unsigned char *src, uint64 len,
		uint32 wut)
{
	uint64 i;
	struct slip_private *priv;
	struct char_dev *cd;
	struct char_ops *ops;

	if(fh) {
	}


	priv = (struct slip_private *)nd->priv;
	cd = priv->hw;
	ops = cd->ops;

//	printf("slip_write: fh:%x nd:%x src:%x len:%x\n",
//			fh, nd, src, len);

	for(i=0; i<len; i++) {
	//	printf("%x ", src[i]);
	}
//	printf("\n");

	len = slip_send_packet((uint8 *)src, len, cd);

//	printf("slip_write: done\n");

	return 0;
}

uint64 slip_init_sock(struct fileh *fh, struct net_dev *nd)
{
	return 0;
}

struct net_ops slip_net_ops = {
	slip_write,
	slip_init,
	slip_init_sock,
	slip_process
};
