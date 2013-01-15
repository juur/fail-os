#ifndef _DEV_H
#define _DEV_H

#include	"klibc.h"
#include	"block.h"
#include	"char.h"

#define COM1	0x3f8
#define	COM2	0x2f8
#define	COM3	0x3e8
#define	COM4	0x2e8

#define	SER_DATA	0x0
#define	SER_INTEN	0x1
#define	SER_LSB_DIV	0x0
#define	SER_MSB_DIV	0x1
#define	SER_CTRL	0x2
#define SER_FCR		0x2
#define	SER_LCR		0x3
#define	SER_MCR		0x4
#define	SER_LSR		0x5
#define	SER_MSR		0x6
#define	SER_SCRATCH	0x7

#define	SER_FCR_ENABLE	(1<<0)
#define	SER_FCR_CLR_RX	(1<<1)
#define SER_FCR_CLR_TX	(1<<2)
#define SER_FCR_DMA_1	(1<<3)
#define	SER_FCR_4B		(1<<6)
#define	SER_FCR_8B		(1<<7)
#define	SER_FCR_14B		(SER_FCR_4B|SER_FCR_8B)

#define	SER_LCR_DLAB	(1<<7)
#define	SER_LCR_SBR		(1<<6)
#define	SER_LCR_STICK	(1<<5)
#define	SER_LCR_EVEN	(1<<4)
#define	SER_LCR_5		0x0
#define	SER_LCR_6		0x1
#define	SER_LCR_7		0x2
#define	SER_LCR_8		0x3

#define	SER_MSR_DCD		(1<<7)
#define	SER_MSR_RI		(1<<6)
#define	SER_MSR_DSR		(1<<5)
#define	SER_MSR_CTS		(1<<4)
#define	SER_MSR_DDCD	(1<<3)
#define	SER_MSR_TERI	(1<<2)
#define	SER_MSR_DDSR	(1<<1)
#define	SER_MSR_DCTS	(1<<0)

#define	SER_MCR_DTR		(1<<0)
#define	SER_MCR_RTS		(1<<1)

#define	SER_LSR_DR			(1<<0)
#define	SER_LSR_THR			(1<<5)
#define	SER_LSR_THR_IDLE	(1<<6)

#define	DEV_NULL	0
#define	DEV_BLOCK	1
#define	DEV_CHAR	2
#define DEV_FS		3
#define	DEV_NET		4
#define	DEV_PROTO	5
#define DEV_ETH		6

#define	CON_MAJOR	5
#define	CON_MINOR	0
#define CON_BUFFER_SIZE	2048
#define	SER_BUFFER_SIZE 2048

#define	SER_MAJOR	4
#define	SER_0_MINOR	64

#define IDE_MAJOR	3

#define	DEV_ID(a,b)	((((uint64)(a))<<16)|(uint64)(b))
#define	DEV_MAJOR(a)	((((uint64)(a))>>16)&0xffff)
#define	DEV_MINOR(a)	(((uint64)(a))&0xffff)

extern struct dev *devs;
extern struct char_ops console_char_ops;
extern struct char_ops serial_char_ops;

struct dev {
	struct dev *next;
	uint64	id;
	uint64	type;
	union {
		struct char_dev *ch_dev;
		struct block_dev *bl_dev;
		struct fs_ops *fs_ops;
		struct net_dev *net_dev;
		struct net_proto *net_proto;
		void *ops;
	} op;
};

#define CON_BUFF	100
#define NUM_SER		1

struct con_private {
	char buf[CON_BUFF];
	struct ring_head *rh;
	int head;
};

struct ser_private {
	char buf[CON_BUFF];
	struct ring_head *rh;
	int head;
	uint16 port;
};

void putch_s(uint16 port, unsigned char c);
void putch(unsigned char c);
void scroll(void);
void move_csr(void);
void cls(void);
void outportb (uint16 _port, uint8 _data);
void outportl (uint16 _port, uint32 _data);
void outportw (uint16 _port, uint16 _data);
uint8 inportb (uint16 _port);
uint16 inportw (uint16 _port);
uint32 inportl (uint16 _port);
void process_key();
uint64 ser_read(struct char_dev *dev, unsigned char *dest, uint64 len);
uint64 ser_write(struct char_dev *dev, unsigned char *src, uint64 len);
bool ser_init(struct char_dev *dev);
uint64 con_read(struct char_dev *dev, unsigned char *dest, uint64 len);
uint64 con_write(struct char_dev *dev, unsigned char *src, uint64 len);
bool con_init(struct char_dev *dev);
struct dev *add_dev(uint64 id, uint64 type, void *ops, char *name, void *priv);
void *find_dev(uint64 id, uint64 type);
void ser_status(uint16 port);
uint64 ser_pending(struct char_dev *dev);
uint64 con_pending(struct char_dev *dev);

static inline void insw (unsigned short _port, void *addr, uint64 _cnt)
{
	__asm__ __volatile__ (
			"cld ; rep ; insw"
			: "=D" (addr), "=c" (_cnt)
			: "d" (_port), "0" (addr), "1" (_cnt)
			);
}


#endif
