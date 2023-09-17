#define _DEV_C
#include <dev.h>
#include <klibc.h>
#include <mem.h>
#include <net.h>
#include <block.h>
#include <char.h>
#include <ioctls.h>

#ifdef WANT_VGA
volatile uint16_t *vga;
static uint16_t attrib = 0x07;
static uint8_t cur_x = 0;
static uint8_t cur_y = 0;
#endif

#ifdef WANT_KEYBOARD
#define MAX_KEYS	0x48

#define KEY_SHIFT	0x2a
#define KEY_CTRL	0x1d
#define KEY_ALT		0x38

const char keymap[MAX_KEYS] = 
	"\0\0"
	"1234567890-=\b"
	"\tqwertyuiop[]\r"
	"\0asdfghjkl;'`"
	"\0\\zxcvbnm,./"
	"\0\0\0 "				// 0x39
	"\0\0\0\0\0\0\0\0";		// 0x47

const char keymap_shift[MAX_KEYS] = 
	"\0\0"
	"!\"#$%^&*()_+\b"
	"\tQWERTYUIOP{}\r"
	"\0ASDFGHJKL:@\0"
	"\0|ZXCVBNM<>?"
	"\0\0\0 "				// 0x39
	"\0\0\0\0\0\0\0\0";		// 0x47
#endif

// race

struct char_dev *con_dev = NULL;

ssize_t cs_read(struct char_dev *dev, char *dest, size_t len)
{
	switch(DEV_MINOR(dev->devid))
	{
		case NUL_MINOR:
			memset(dest, 0, len);
			return len;
	}
	return 0;
}

ssize_t cs_pending(struct char_dev *dev)
{
	return 0;
}

ssize_t cs_write(struct char_dev *dev, const char *src, size_t len)
{
	return 0;
}

int cs_ioctl(struct char_dev *dev, struct task *task, unsigned long request, unsigned long cmd)
{
	return -EINVAL;
}

int cs_init(struct char_dev *dev)
{
	return 0;
}

static ssize_t con_read(struct char_dev *_dev, char *dest, size_t len)
{
	//if(!dev) return -1;
	size_t cnt = 0;
	uint8_t *dst_ptr = (uint8_t *)dest;
	struct con_private *p = (struct con_private *)con_dev->priv;
	while(len-- && ring_read(p->rh,dst_ptr++)) {
		cnt++;
	}
	//printf("con read: %ld\n", cnt);
	return cnt;
}

static ssize_t con_pending(struct char_dev *dev)
{
	//if(!dev) return -1;
	struct con_private *p = (struct con_private *)con_dev->priv;
	return p->rh->data;
}

ssize_t con_write(struct char_dev *const _dev, const char *const src, const size_t len)
{
	//if(!dev) return -1;
	size_t i;
	for(i=0;i<len;i++)
	{
		if(!src[i]) return i;
		//putch(src[i]);
#ifdef WANT_SERIAL
		putch_s(COM1, src[i]);
#endif
	}
	return i;
}

void setup_tsc(void)
{
}

void delay_ms(uint32_t ms)
{
}

inline uint64_t rdtsc(void)
{
	uint32_t a,b;
	__asm__ volatile ("rdtsc":"=a" (a), "=d"(b)::"memory");
	return ((uint64_t)a|((uint64_t)b)<<32);
}

#ifdef WANT_SERIAL
__attribute__((nonnull)) static ssize_t ser_read(struct char_dev *const dev, char *const dest, const size_t len)
{
	size_t cnt = 0;
	size_t rem = len;
	
	struct ser_private *p = (struct ser_private *)dev->priv;
	uint8_t *dst = (uint8_t *)dest;

	//printf("ser_read: port:0x%x dest:%p len:0x%lx rh:0x%p rh->data:%d\n",
	//		p->port,
	//	    (void *)dest,
	//		len,
	//		(void *)p->rh,
	//		p->rh->data);

	sti();
	while(rem) {
		while(!p->rh->data) {
			pause();
		}
		//printf("ser_read: unpausing\n");
		//printf("ser_read: port:0x%x has data: cnt:%lx rem:%lx\n", p->port, cnt, rem);
		while(rem && ring_read(p->rh,dst++)) { 
			cnt++;
			rem--;
		}
		//printf("ser_read: port:0x%x cnt:%lx rem:%lx\n", p->port, cnt, rem);

	}
	cli();
	
	//printf("ser_read: port:0x%x cnt:%lx\n", p->port, cnt);
	return cnt;
}

__attribute__((nonnull)) static ssize_t ser_pending(struct char_dev *dev)
{
	struct ser_private *p = (struct ser_private *)dev->priv;
	return p->rh->data;
}

__attribute__((nonnull)) static ssize_t ser_write(struct char_dev *dev, const char *src, size_t len)
{
	size_t i;
	struct ser_private *p = (struct ser_private *)dev->priv;
	for(i=0;i<len;i++)
	{
		putch_s(p->port, src[i]);
	}
	return len;
}
#endif

int con_init(struct char_dev *dev)
{
	struct con_private *cp;

	if(con_dev != NULL) {
		printf("Attempt to init two consoles\n"); 
		return -EINVAL;
	}

	con_dev = dev;
	cp = dev->priv;

	if(!cp && (cp = dev->priv = (void *)kmalloc(sizeof(struct con_private), "con_private", NULL, 0)) == NULL)
		return -ENOMEM;
	
	cp->rh = ring_init(CON_BUFFER_SIZE, NULL);

	return 0;
}

int con_ioctl(struct char_dev *dev, struct task *task, unsigned long request, unsigned long cmd)
{
	printf("con_ioctl\n");
	return -EINVAL;
}

#ifdef WANT_SERIAL
__attribute__((nonnull))
static int ser_init(struct char_dev *dev)
{
	struct ser_private *cp;
	uint16_t port;

	//if(!dev)
	//	return -1;

	cp = dev->priv;

	if(!cp && (cp = dev->priv = (void *)kmalloc(sizeof(struct ser_private), "ser_private", NULL, 0)) == NULL) {
		printf("ser_init: unable to allocate memory ser_private\n");
		return -ENOMEM;
	}

	//memset(dev->private, 0, sizeof(struct ser_private));
	if((cp->rh = ring_init(SER_BUFFER_SIZE, NULL)) == NULL)
		goto fail;

	switch(DEV_MINOR(dev->devid))
	{
		case SER_0_MINOR:
			port = COM1;
			break;
		case SER_1_MINOR:
			port = COM2;
			break;
		default:
			printf("ser_init: invalid minor id %x\n", DEV_MINOR(dev->devid));
			goto fail;
			break;
	}
	//printf("ser_init: setting port to 0x%x for devid %lx\n", port, dev->devid);
	cp->port = port;

	return 0;

fail:
	if(cp->rh) kfree(cp->rh);
	if(cp) kfree(cp);
	return -1;
}

static int ser_ioctl(struct char_dev *dev, struct task *task, unsigned long cmd, unsigned long arg)
{
	switch(cmd)
	{
		case TCGETS:
			{
				struct termios *tios = (void *)arg;
				tios->c_ispeed = B38400;
				tios->c_ospeed = B38400;
				tios->c_cflag  = CS8|CREAD;
				tios->c_lflag  = ECHO|ECHOE|ECHOK|ECHOK|ISIG|ICANON|IEXTEN;
				tios->c_iflag  = ICRNL|IXON;
				tios->c_oflag  = OPOST|ONLCR;
				return 0;
			}
			break;
		case TCSETS:
			{
				struct termios *tios = (void *)arg;
				printf("ser_ioctl: TCSETS: c_cflag: %x c_lflag: %x c_iflag: %x c_oflag: %x\n",
						tios->c_cflag,
						tios->c_lflag,
						tios->c_iflag,
						tios->c_oflag);
				return 0;
			}
			break;
		case TIOCNOTTY:
			/* TODO give up controlling terminal. SIGHUP and SIGCONT to all foreground process groups if
			 * this process was the session leader */
			return 0;
			break;
		default:
			printf("ser_ioctl: unsupported ioctl %lx\n", cmd);
			return -EINVAL;
	}
}

const struct char_ops serial_char_ops = {
	"serial_char_ops",
	ser_read,
	ser_write,
	ser_init,
	ser_pending,
	ser_ioctl
};
#endif


struct dev *devs;

void free_dev(struct dev *const d)
{
	if(!d) 
		return;
}

struct dev *add_dev(uint64_t id, uint64_t type, const void *ops, const char *name, 
		void *priv)
{
	struct dev *ret = NULL;

	if((ret = kmalloc(sizeof(struct dev), "dev", NULL, 0)) == NULL)
		goto fail;

	memset(&ret->name, 0, DEVNAME);
	strncpy((char *)&ret->name, name, DEVNAME-1);

	ret->id = id;
	ret->type = type;

	//printf("add_dev: %x(%x.%x) %x %x \"%s\" ret=%x\n", id, DEV_MAJOR(id), DEV_MINOR(id), type, ops, name, name, ret);
	switch(type)
	{
		case DEV_BLOCK:
			if((ret->op.bl_dev = kmalloc(sizeof(struct block_dev), "block_dev", NULL, 0)) == NULL)
				goto fail;
			ret->op.bl_dev->ops = ops;
			ret->op.bl_dev->devid = id;
			ret->op.bl_dev->priv = priv;
			//printf("add_dev: adding: ops=%s\n", ret->op.bl_dev->ops->name);
			((struct block_ops *)ops)->init(ret->op.bl_dev);
			break;
		case DEV_CHAR:
			if((ret->op.ch_dev = kmalloc(sizeof(struct char_dev),"char_dev", NULL, 0)) == NULL)
				goto fail;
			ret->op.ch_dev->ops = ops;
			ret->op.ch_dev->devid = id;
			ret->op.ch_dev->priv = priv;
			//printf("add_dev: adding: ops=%s\n", ret->op.ch_dev->ops->name);
			((struct char_ops *)ops)->init(ret->op.ch_dev);
			break;
		case DEV_FS:
			break;
		case DEV_NET:
			if((ret->op.net_dev = kmalloc(sizeof(struct net_dev),"net_dev", NULL, 0)) == NULL)
				goto fail;
			ret->op.net_dev->ops = ops; /* e.g. struct eth_ops */
			//printf("add_dev: adding: ops=%s\n", ret->op.net_dev->ops->name);
			// net_init() does init;
			break;
		case DEV_PROTO:
			if((ret->op.net_proto =  kmalloc(sizeof(struct net_proto),"net_proto", NULL, 0)) == NULL)
				goto fail;
			ret->op.net_proto->ops = ops;
			//printf("add_dev: adding: ops=%s\n", ret->op.net_proto->ops->name);
			// net_init() does init;
			break;
		default:
			printf("add_dev: attempting to add unknown device type 0x%lx\n", type);
			break;
	}

	//	printf("\ndev: added:%s @ %x id:%x ops:%x name:%s\n", 
	//			(type==DEV_BLOCK)?"block":"char",ret, id, ops, name);

	ret->next = devs;
	devs = ret;

	return ret;
fail:
	if(ret) kfree(ret);
	return NULL;
}

void *find_dev(uint64_t id, uint64_t type)
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

struct dev *find_dev_name(const char *name, uint64_t type)
{
	struct dev *d;

	for(d = devs; d; d=d->next)
	{
		if(type && (d->type != type)) continue;
		//printf("check %x==%x %s==%s\n", type, d->type, name, d->name);
		if(strncmp(name, d->name, DEVNAME)) continue;
		return d;
	}

	return NULL;
}


void process_key()
{
#ifdef WANT_KEYBOARD

	if(!(inportb(KBD_STAT) & KBD_SR_OUTB)) return;

    bool shift = false, alt = false, ctrl = false;
	uint8_t raw=0, oldraw, running=1;
	struct char_dev *tty;
	struct con_private *ttyp;
	
	do {
		oldraw = raw;
		raw = inportb(KBD_DATA);
		if(raw==oldraw) { 
//			printf("end"); 
			running=0; continue; }
		else if(raw > 0x80) {
		} else {
			switch(raw) {
				case KEY_SHIFT:
//					printf("[shift]");
					shift = true;
					break;
				case KEY_CTRL:
//					printf("[ctrl]");
					ctrl = true;
					break;
				default:
//					printf("c=%x",ctrl);
					if(raw < MAX_KEYS && keymap[raw]) {
						tty = find_dev(DEV_ID(CON_MAJOR,CON_MINOR), DEV_CHAR);
						if (!tty)
							break;
						ttyp = (struct con_private *)tty->priv;
						if(shift && !ctrl && !alt) {
							ring_write(ttyp->rh, keymap_shift[raw]);
						} else if(ctrl && !shift && !alt) {
//							printf("key: ctrl");
							switch(keymap[raw]) {
								case 'l':
									//cls();
									break;
								case 'k':
									dump_pools();
									break;
							}
						} else {
							ring_write(ttyp->rh, keymap[raw]);
						}
					} else {
						//printf("[%x]", raw);	
					}
					break;
			}
		}
	} while(running);
#endif
}
	

uint8_t inportb (unsigned short _port)
{
	uint8_t rv = 0;
	__asm__ volatile ("inb %1, %0" : "=a" (rv) : "dN" (_port));
	return rv;
}

uint16_t inportw (unsigned short _port)
{
	uint16_t rv = 0;
	__asm__ volatile ("inw %1, %0" : "=a" (rv) : "dN" (_port));
	return rv;
}

uint32_t inportl (unsigned short _port)
{
	uint32_t rv = 0;
	__asm__ volatile ("inl %1, %0" : "=a" (rv) : "dN" (_port));
	return rv;
}

void outportb (unsigned short _port, uint8_t _data)
{
	__asm__ volatile ("outb %1, %0" :: "dN" (_port), "a" (_data):"memory");
}

void outportw (unsigned short _port, uint16_t _data)
{
	__asm__ volatile ("outw %1, %0" :: "dN" (_port), "a" (_data):"memory");
}

void outportl (uint16_t _port, uint32_t _data)
{
	__asm__ volatile ("outl %1, %0" :: "dN" (_port), "a" (_data):"memory");
}

#ifdef WANT_VGA
#define SCREEN_COLS 80U
#define SCREEN_ROWS 25U

__attribute__((nonnull))
uint16_t volatile *memsetw(uint16_t volatile *dest, uint16_t val, size_t count)
{
	uint16_t volatile *temp = dest;
	size_t cnt;

    if (!count)
        return NULL;

	for(cnt = count; cnt; count--) 
        *(temp++) = val;

    return dest;
}

void scroll(void)
{
	const uint16_t blank = 0x20 | (attrib << 8);

	if(cur_y >= SCREEN_ROWS)
	{
		const uint16_t offset = cur_y - SCREEN_ROWS + 1;

		volatile uint16_t *dp = vga;
		const volatile uint16_t *sp = (vga + (offset * SCREEN_COLS));

		size_t count = (SCREEN_ROWS - offset) * SCREEN_COLS;

		for(; count; count--)
			*dp++ = *sp++;
		
		memsetw(vga + ((SCREEN_ROWS - offset) * SCREEN_COLS), 
				blank, 
				SCREEN_COLS);

		cur_y = SCREEN_ROWS - 1;
	}
}

void move_csr(void)
{
	const uint16_t temp = (cur_y * SCREEN_COLS) + cur_x;
	outportb(0x3d4, 0x0e);
	outportb(0x3d5, (temp >> 8) & 0xff);
	outportb(0x3d4, 0x0f);
	outportb(0x3d5, temp & 0xff);
}

void cls(void)
{
	uint8_t i;
	const uint16_t blank = 0x20 | (attrib << 8);

	for(i=0;i<SCREEN_ROWS;i++)
		memsetw(vga + (i*SCREEN_COLS), blank, SCREEN_COLS);
	
	cur_x = 0;
	cur_y = 0;
	move_csr();
}
#endif

#ifdef WANT_SERIAL
void putch_s(const uint16_t port, const unsigned char c)
{
	while( (inportb(port+SER_LSR) & SER_LSR_THR) == 0) {
		pause();
	}
	outportb(port, c);
	
	if(c=='\n') putch_s(port, '\r');
}

bool getch_s(uint16_t port, unsigned char *c)
{
	if( (inportb(port + SER_LSR) & SER_LSR_DR) == 0 ) return false;

	*c = inportb(port + SER_DATA);
	return true;
}

void ser_status(uint16_t port)
{
	uint8_t ch;
	uint8_t st;
	struct char_dev *d;
	struct ser_private *sp;

	//printf("ser_status: %x\n", port);

	d = find_dev(DEV_ID(SER_MAJOR,SER_0_MINOR + port), DEV_CHAR);
	if(!d) {
		printf("ser_status: can't find port for %x\n", port);
		return;
	}

	sp = d->priv;
	if(!sp) {
		printf("ser_status: sp is null for %x\n", port);
		return;
	}


	st = inportb(sp->port + SER_MSR);
	//printf("serial: 0x%x: MSR=%0x\n", sp->port, st);

	/*
	if(st) { 
		printf("%x MSR: %s %s %s %s %s %s %s %s\n", port,
			(st & SER_MSR_DCD) ? "DCD" : "",
			(st & SER_MSR_RI) ? "DI" : "",
			(st & SER_MSR_DSR) ? "DSR" : "",
			(st & SER_MSR_CTS) ? "CTS" : "",
			(st & SER_MSR_DDCD) ? "DDCD" : "",
			(st & SER_MSR_TERI) ? "TERI" : "",
			(st & SER_MSR_DDSR) ? "DDSR" : "",
			(st & SER_MSR_DCTS) ? "DCTS" : ""
			); 
	}
	*/

	st = inportb(sp->port+SER_LSR);
	//printf("LSR: %x\n", st);

	while((st & SER_LSR_DR) == SER_LSR_DR) 
	{
		ch = inportb(sp->port + SER_DATA);
		//if (ch < 0x20)
		//	printf("serial: read 0x%2x\n", ch);
		/* epic kludge */
		if (ch == 0xd)
			ch = 0xa;
		ring_write(sp->rh, ch);
		st = inportb(sp->port + SER_LSR);
	}
	//printf("ser done\n");
	//printf("\n");
	//print_ring(sp->rh);
}
#endif

#ifdef WANT_VGA
void putch(unsigned char c)
{
	volatile uint16_t *where;
	const short att = (attrib << 8);

	if (c == 0x08) {  // Backspace
		if(cur_x > 0) 
			cur_x--;
	} else if (c == 0x09) {  // Tab
		cur_x = (cur_x + 8) & ~(8 - 1);
	} else if (c == '\r') {
		cur_x = 0;
	} else if (c == '\n') {  // LF
		cur_x = 0;
		cur_y++;
	} else if( c >= ' ' ) {
		where = vga + ((cur_y * SCREEN_COLS) + cur_x);
		*where = c | att;
		cur_x++;
	}

	if( cur_x > SCREEN_COLS ) {
		cur_x = 0;
		cur_y++;
	}

	//scroll();
	move_csr(); // optimise a little

}
#endif

const struct char_ops console_char_ops = {
	"console_char_ops",
	con_read,
	con_write,
	con_init,
	con_pending,
	con_ioctl
};

const struct char_ops char_special_ops = {
	"char_special_ops",
	cs_read,
	cs_write,
	cs_init,
	cs_pending,
	cs_ioctl
};
