#ifndef _DEV_H
#define _DEV_H

#include	"klibc.h"
#include	"block.h"
#include	"char.h"

#define COM1	0x3f8
#define	COM2	0x2f8
#define	COM3	0x3e8
#define	COM4	0x2e8

#define KBD_DATA	0x60
#define	KBD_STAT	0x64
#define	KBD_CMD		0x64

#define KBD_SR_OUTB	0x1
#define	KBD_SR_INB	0x2
#define	KBD_SR_SYS	0x4
#define	KBD_SR_CD	0x8
#define	KBD_SR_TO_ERR	0x40
#define	KBD_SR_PR_ERR	0x80

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

/* FIFO Control Register */
#define	SER_FCR_ENABLE	(1<<0)
#define	SER_FCR_CLR_RX	(1<<1)
#define SER_FCR_CLR_TX	(1<<2)
#define SER_FCR_DMA_1	(1<<3)
/* 6+7 control FIFO int trigger */
#define SER_FCR_1B		0x0
#define	SER_FCR_4B		(1<<6)
#define	SER_FCR_8B		(1<<7)
#define	SER_FCR_14B		(1<<6|1<<7)

/* Line Control Register */
/* 1=RBR,THR,IER 0=DLL,DLM */
#define	SER_LCR_DLAB	(1<<7)
#define	SER_LCR_SBR		(1<<6)
/* bits 3,4,5 control parity */
#define	SER_LCR_NOP		0x00
#define	SER_LCR_ODDP	0x08
#define SER_LCR_EVENP	0x18
#define SER_LCR_HIGHP	0x28
#define SER_LCR_LOWP	0x38
/* bit 2 controls stop */
#define SER_LCR_2S		(1<<2)
/* bits 0+1 control word length */
#define	SER_LCR_8		0x3
#define	SER_LCR_7		0x2
#define	SER_LCR_6		0x1
#define	SER_LCR_5		0x0

#define	SER_MSR_DCD		(1<<7)
#define	SER_MSR_RI		(1<<6)
#define	SER_MSR_DSR		(1<<5)
#define	SER_MSR_CTS		(1<<4)
/* change in CD */
#define	SER_MSR_DDCD	(1<<3)
/* Trailing Edge RI */
#define	SER_MSR_TERI	(1<<2)
/* change to DSR */
#define	SER_MSR_DDSR	(1<<1)
/* change to CTS */
#define	SER_MSR_DCTS	(1<<0)

#define	SER_MCR_DTR		(1<<0)
#define	SER_MCR_RTS		(1<<1)
#define SER_MCR_AUX1	(1<<2)
#define SER_MCR_AUX2	(1<<3)
#define SER_MCR_LOOP	(1<<4)

#define	SER_LSR_DR			(1<<0)
#define SER_LSR_OR_ERR		(1<<1)
#define SER_LSR_P_ERR		(1<<2)
#define SER_LSR_FR_ERR		(1<<3)
#define SER_LSR_BREAK		(1<<4)
#define	SER_LSR_THR			(1<<5)
#define	SER_LSR_THR_IDLE	(1<<6)
#define SER_LSR_FIFO_ERR	(1<<7)

#define	DEV_NULL	0
#define	DEV_BLOCK	1
#define	DEV_CHAR	2
#define DEV_FS		3
#define	DEV_NET		4
#define	DEV_PROTO	5
#define DEV_ETH		6

#define	CON_MAJOR	5
#define	CON_MINOR	0
#define CON_BUFFER_SIZE	32
#define	SER_BUFFER_SIZE 32

#define	SER_MAJOR	4
#define	SER_0_MINOR	64
#define	SER_1_MINOR	65

#define IDE_MAJOR	3

#define	DEV_ID(a,b)	    ((((dev_t)(a))<<16)|(dev_t)(b))
#define	DEV_MAJOR(a)	((((dev_t)(a))>>16)&0xffff)
#define	DEV_MINOR(a)	(((dev_t)(a))&0xffff)

extern struct dev *devs;
extern const struct char_ops console_char_ops;
extern const struct char_ops serial_char_ops;

#define DEVNAME	16

struct dev {
	struct dev *next;
	uint64_t	id;
	uint64_t	type;
	char	name[DEVNAME];
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
	uint16_t port;
};

void putch_s(uint16_t port, unsigned char c);
void putch(unsigned char c);
void scroll(void);
void move_csr(void);
void cls(void);
void outportb (uint16_t _port, uint8_t _data);
void outportl (uint16_t _port, uint32_t _data);
void outportw (uint16_t _port, uint16_t _data);
uint8_t inportb (uint16_t _port);
uint16_t inportw (uint16_t _port);
uint32_t inportl (uint16_t _port);
void process_key(void);
//ssize_t ser_read(struct char_dev *dev, char *dest, size_t len)__attribute__((nonnull));
//ssize_t ser_write(struct char_dev *dev, const char *src, size_t len)__attribute__((nonnull));
//int ser_init(struct char_dev *dev)__attribute__((nonnull));
ssize_t con_read(struct char_dev *dev, char *dest, size_t len)__attribute__((nonnull));
ssize_t con_write(struct char_dev *dev, const char *src, size_t len)__attribute__((nonnull));
int con_init(struct char_dev *dev)__attribute__((nonnull));
struct dev *add_dev(uint64_t id, uint64_t type, const void *ops, char *name, void *priv)__attribute__((nonnull(3)));
void *find_dev(uint64_t id, uint64_t type);
struct dev *find_dev_name(const char *name, uint64_t type)__attribute__((nonnull));
void ser_status(uint16_t port);
//long ser_pending(struct char_dev *dev)__attribute__((nonnull));
long con_pending(struct char_dev *dev)__attribute__((nonnull));

__attribute__((unused)) static inline void insw (unsigned short _port, void *addr, uint64_t _cnt)
{
	__asm__ volatile (
			"cld ; rep ; insw"
			: "=D" (addr), "=c" (_cnt)
			: "d" (_port), "0" (addr), "1" (_cnt)
			: "memory"
			);
}

__attribute__((unused)) static inline void outw (unsigned short _port, const void *addr, uint64_t _cnt)
{
	__asm__ volatile (
			"cld ; rep ; outsw"
			: "=S" (addr), "=c" (_cnt)
			: "d" (_port), "0" (addr), "1" (_cnt)
			: "memory"
			);
}

#endif
// vim: set ft=c:
