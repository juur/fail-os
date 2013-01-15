#define _DEV_C
#include "dev.h"
#include "klibc.h"
#include "mem.h"
#include "net.h"
#include "block.h"
#include "char.h"

unsigned short *vga;
uint16 attrib = 0x07;
int cur_x = 0;
int cur_y = 0;

#define MAX_KEYS	0x48

#define KEY_SHIFT	0x2a
#define KEY_CTRL	0x1d
#define KEY_ALT		0x38

char keymap[MAX_KEYS] = 
	"\0\0"
	"1234567890-=\b"
	"\tqwertyuiop[]\r"
	"\0asdfghjkl;'`"
	"\0\\zxcvbnm,./"
	"\0\0\0 "				// 0x39
	"\0\0\0\0\0\0\0\0";		// 0x47

char keymap_shift[MAX_KEYS] = 
	"\0\0"
	"!\"#$%^&*()_+\b"
	"\tQWERTYUIOP{}\r"
	"\0ASDFGHJKL:@\0"
	"\0|ZXCVBNM<>?"
	"\0\0\0 "				// 0x39
	"\0\0\0\0\0\0\0\0";		// 0x47


struct char_ops console_char_ops = {
	con_read,
	con_write,
	con_init,
	con_pending

};

struct char_ops serial_char_ops = {
	ser_read,
	ser_write,
	ser_init,
	ser_pending
};

// race

struct char_dev *con_dev = NULL;

uint64 con_read(struct char_dev *dev, unsigned char *dest, uint64 len)
{
	int cnt = 0;
	struct con_private *p = (struct con_private *)con_dev->private;
	//printf("con read\n");
	while(len-- && ring_read(p->rh,dest++)) cnt++;
	return cnt;
}

uint64 con_pending(struct char_dev *dev)
{
	struct con_private *p = (struct con_private *)con_dev->private;
	return p->rh->data;
}

uint64 con_write(struct char_dev *dev, unsigned char *src, uint64 len)
{
	uint64 i;
	for(i=0;i<len;i++)
	{
		putch_s(COM1, src[i]);
		putch(src[i]);
	}
	return len;
}

uint64 ser_read(struct char_dev *dev, unsigned char *dest, uint64 len)
{
	uint8 cnt = 0;
	struct ser_private *p = (struct ser_private *)dev->private;
	unsigned char *dst = dest;

	//printf("\nser_re:ad(%lx,%lx,%lx) cnt=%lx\n", dev, dest, len, cnt);

	sti();
	while(len) { 
		while(!p->rh->data) hlt();
		while(len && ring_read(p->rh,dst++)) { 
			cnt++;
			len--;
		}
	}
	
	//printf("\nser_read(%lx,%lx,%lx) cnt=%lx\n", dev, dest, len, cnt);
	return cnt;
}

uint64 ser_pending(struct char_dev *dev)
{
	struct ser_private *p = (struct ser_private *)dev->private;
	return p->rh->data;
}

uint64 ser_write(struct char_dev *dev, unsigned char *src, uint64 len)
{
	uint64 i;
	struct ser_private *p = (struct ser_private *)dev->private;
	//printf("ser_write: dev=%lx, src=%lx, len=%lx, port=%lx\n", dev, src, len, p->port);
	for(i=0;i<len;i++)
	{
		putch_s(p->port, src[i]);
	}
	return len;
}

bool con_init(struct char_dev *dev)
{
	struct con_private *cp;

	if(con_dev != NULL) {
		printf("Attempt to init two consoles\n"); 
		return false;
	}

	con_dev = dev;

	dev->private = (void *)kmalloc(sizeof(struct con_private), "con_private", NULL);
	cp = (struct con_private *)dev->private;
	cp->rh = ring_init(CON_BUFFER_SIZE, NULL);
	return true;
}

bool ser_init(struct char_dev *dev)
{
	struct ser_private *cp;
	uint16 port;
	if(!dev->private) {
		dev->private = (void *)kmalloc(sizeof(struct ser_private), "ser_private", NULL);
	}
	//memset(dev->private, 0, sizeof(struct ser_private));
	cp = (struct ser_private *)dev->private;
	cp->rh = ring_init(SER_BUFFER_SIZE, NULL);
	switch(DEV_MINOR(cp->port))
	{
		case 0:
			port = COM1;
			break;
			/*
		case 1:
			port = COM2;
			break;
			*/
		default:
			printf("\nser_init: invalid port\n");
			kfree(dev->private);
			return false;
			break;
	}
	cp->port = port;

	return true;
}

struct dev *devs;

void free_dev(struct dev *d)
{
}

struct dev *add_dev(uint64 id, uint64 type, void *ops, char *name, 
		void *private)
{
	struct dev *ret = kmalloc(sizeof(struct dev), "dev", NULL);
	if(!ret) return NULL;
	ret->id = id;
	ret->type = type;
	ret->next = devs;
	devs = ret;
//	printf("add_dev: %x %x %x \"%s\" ret=%x\n", id, type, ops, name, name, ret);
	switch(type)
	{
		case DEV_BLOCK:
			ret->op.bl_dev = kmalloc(sizeof(struct block_dev), "block_dev", NULL);
			ret->op.bl_dev->ops = ops;
			ret->op.bl_dev->devid = id;
			ret->op.bl_dev->private = private;
			((struct block_ops *)ops)->init(ret->op.bl_dev);
			break;
		case DEV_CHAR:
			ret->op.ch_dev = kmalloc(sizeof(struct char_dev),"char_dev", NULL);
			ret->op.ch_dev->ops = ops;
			ret->op.ch_dev->devid = id;
			((struct char_ops *)ops)->init(ret->op.ch_dev);
			break;
		case DEV_NET:
			ret->op.net_dev = kmalloc(sizeof(struct net_dev),"net_dev", NULL);
			ret->op.net_dev->ops = ops;
			// net_init() does init;
			break;
		case DEV_PROTO:
			ret->op.net_proto =  kmalloc(sizeof(struct net_proto),"net_proto", NULL);
			ret->op.net_proto->ops = ops;
			// net_init() does init;
			break;
		default:
			break;
	}
//	printf("\ndev: added:%s @ %x id:%x ops:%x name:%s\n", 
//			(type==DEV_BLOCK)?"block":"char",ret, id, ops, name);
	return ret;
}

void *find_dev(uint64 id, uint64 type)
{
	struct dev *d;

//	printf("\nfind_dev: looking for id=%x, type=%x\n", id, type);

	for(d = devs; d; d=d->next)
	{
//		printf("find_dev: d=%x, d->type:%x, d->id:%x\n",
//				d, d->type, d->id);
		if(d->type != type) continue;
		if(d->id != id) continue;
//		printf("find_dev: %x %x\n", d, d->op.ops);
		return d->op.ops;
	}

	return NULL;
}


void process_key()
{
	uint8 raw=0, oldraw, running=1;
	bool shift = false, alt = false, ctrl = false;
	struct char_dev *tty;
	struct con_private *ttyp;
	
	do {
		oldraw = raw;
		raw = inportb(0x60);
		if(raw==oldraw) { running=0; continue; }
		if(raw > 0x80) {
		} else {
			switch(raw) {
				case KEY_SHIFT:
					shift = true;
					break;
				case KEY_CTRL:
					ctrl = true;
					break;
				default:
					if(raw < MAX_KEYS && keymap[raw]) {
						tty = find_dev(DEV_ID(CON_MAJOR,CON_MINOR), DEV_CHAR);
						ttyp = (struct con_private *)tty->private;
						if(shift && !ctrl && !alt) {
							ring_write(ttyp->rh, keymap_shift[raw]);
						} else if(ctrl && !shift && !alt) {
							switch(keymap[raw]) {
								case 'l':
									cls();
									break;
								case 'k':
									dump_pools();
									break;
							}
						} else {
							ring_write(ttyp->rh, keymap[raw]);
						}
					} else {
//						printf("[%x]", raw);	
					}
					break;
			}
		}
	} while(running);
}
	

uint8 inportb (unsigned short _port)
{
	uint8 rv = 0;
	__asm__ __volatile__ ("inb %1, %0" : "=a" (rv) : "dN" (_port));
	return rv;
}

uint16 inportw (unsigned short _port)
{
	uint16 rv = 0;
	__asm__ __volatile__ ("inw %1, %0" : "=a" (rv) : "dN" (_port));
	return rv;
}

uint32 inportl (unsigned short _port)
{
	uint32 rv = 0;
	__asm__ __volatile__ ("inl %1, %0" : "=a" (rv) : "dN" (_port));
	return rv;
}

void outportb (unsigned short _port, uint8 _data)
{
	__asm__ __volatile__ ("outb %1, %0" : : "dN" (_port), "a" (_data));
}

void outportw (unsigned short _port, uint16 _data)
{
	__asm__ __volatile__ ("outw %1, %0" : : "dN" (_port), "a" (_data));
}

void outportl (uint16 _port, uint32 _data)
{
	__asm__ __volatile__ ("outl %1, %0" : : "dN" (_port), "a" (_data));
}

void scroll(void)
{
	uint16 blank, temp;

	blank = 0x20 | (attrib << 8);

	if(cur_y > 24)
	{
		temp = cur_y - 24;
		(void)memcpy((char *)vga, (char *)(vga+temp*80), (25-temp)*80*2);
		(void)memsetw((short *)vga+(25-temp)*80,blank,80);
		cur_y = 24;
	}
}

void move_csr(void)
{
	uint16 temp;
	temp = (cur_y * 80) + cur_x;
	outportb(0x3d4, 0x0f);
	outportb(0x3d5, temp & 0xff);
	outportb(0x3d4, 0x0e);
	outportb(0x3d5, (temp >> 8) & 0xff);
}

void cls(void)
{
	uint16 blank;
	int i;

	blank = 0x20 | (attrib << 8);
	for(i=0;i<25;i++)
		(void)memsetw((short *)vga+(i*80), blank, 80);

	cur_x = 0;
	cur_y = 0;
	move_csr();
}


void putch_s(uint16 port, unsigned char c)
{
	while( (inportb(port+SER_LSR) & SER_LSR_THR) == 0) {
		pause();
	}
	outportb(port, c);
	
	if(c=='\n') putch_s(port, '\r');
}

bool getch_s(uint16 port, unsigned char *c)
{
	if( (inportb(port + SER_LSR) & SER_LSR_DR) == 0 ) return false;

	*c = inportb(port + SER_DATA);
	return true;
}

void ser_status(uint16 port)
{
	uint8 ch;
	uint8 st;
	struct char_dev *d;
	struct ser_private *sp;

//	printf("ser_status: %x\n", port);


	d = find_dev(DEV_ID(SER_MAJOR,SER_0_MINOR+port), DEV_CHAR);
	if(!d) {
		printf("ser_status: can't find port for %x\n", port);
		return;
	}

	sp = d->private;
	if(!sp) {
		printf("ser_status: sp is null for %x\n", port);
		return;
	}

//	print_ring(sp->rh);

/*
	st = inportb(port+SER_MSR);
	if(st) { printf("%x MSR: %s %s %s %s %s %s %s %s\n", port,
			(st & SER_MSR_DCD) ? "DCD" : "",
			(st & SER_MSR_RI) ? "DI" : "",
			(st & SER_MSR_DSR) ? "DSR" : "",
			(st & SER_MSR_CTS) ? "CTS" : "",
			(st & SER_MSR_DDCD) ? "DDCD" : "",
			(st & SER_MSR_TERI) ? "TERI" : "",
			(st & SER_MSR_DDSR) ? "DDSR" : "",
			(st & SER_MSR_DCTS) ? "DCTS" : ""
			); }
*/			
	st = inportb(sp->port+SER_LSR);
/*	
	if(st & SER_LSR_DR ) { printf("%x LSR: %s\n", port,
			(st & SER_LSR_DR) ? "DR" : ""
		  ); }
*/		  

	while(st & SER_LSR_DR) 
	{
		bool tmp;
		tmp = getch_s(sp->port, &ch);
		if(!tmp) continue;
		ring_write(sp->rh, ch);
//skip:
		st = inportb(sp->port+SER_LSR);
	}

}

void putch(unsigned char c)
{
	unsigned short *where;
	unsigned att = attrib << 8;

//	return;

	switch( c )
	{
		case 0x08:  // Backspace
			if(cur_x != 0) cur_x--;
			break;
		case 0x09:  // Tab
			cur_x = (cur_x + 8) & ~(8 - 1);
			break;
		case '\r':  // CR
			cur_x = 0;
			break;
		case '\n':  // LF
			cur_x = 0;
			cur_y++;
			break;
	}

	if( c >= ' ' ) {
		where = vga + ((cur_y*80) + cur_x);
		*where = c | att;
		cur_x++;
	}

	if( cur_x >= 80 ) {
		cur_x = 0;
		cur_y++;
	}

	scroll();
	// move_csr(); // optimise a little
}
