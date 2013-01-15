#define _LIBC_C
#include "klibc.h"
#include "dev.h"
#include "mem.h"

void itoa (char *buf, int base, uint64 d, bool pad, int size)
{
	char *p = buf, *p1, *p2;
	uint64 ud = d;
	uint64 divisor = 10;
	uint64 remainder;

	if(base=='d' && (long)d < 0)
	{
		*p++ = '-';
		buf++;
		ud = -d;
	} else if(base=='x') {
		divisor = 16;
	}

	do {
		remainder = ud % divisor;
		*p++ = (char)((remainder < 10) ? remainder + '0' : remainder + 'a' - 10);
	} while (ud /= divisor);

	*p = 0;

	p1 = buf;
	p2 = p - 1;

	while(p1<p2)
	{
		char tmp = *p1;
		*p1 = *p2;
		*p2 = tmp;
		p1++;
		p2--;
	}
}

#define _INT	4
#define	_SHORT	2
#define	_LONG	8

void vprintf(const char *format, va_list ap)
{
	char c;
	char *p;
	char buf[64],buf2[64];
	int len = _INT;
	bool pad = false;
	int i,l;

	memset(buf2, '0', 63); buf[63] = '\0';

	while ((c = *format++) != 0)
	{
		if ( c!= '%' ) {
			putsn(&c, 1); 
		} else {
next:
			c = *format++;
			p = buf;
			switch(c)
			{
				case 'p':
					len = _LONG;
					c = 'x';
					goto forcex;
				case '0':
					pad = true;
					goto next;
				case 'h':
					len = _SHORT;
					goto next;
				case 'l':
					len = _LONG;
					goto next;
				case 'u':
				case 'x':
forcex:
					switch(len) {
						case _SHORT:
							itoa(buf,c,(uint64)va_arg(ap, unsigned int), pad, len);
							break;
						case _INT:
							itoa(buf,c,(uint64)va_arg(ap, uint32), pad, len);
							break;
						case _LONG:
							itoa(buf,c,(uint64)va_arg(ap, uint64), pad, len);
							break;
					}
					goto padcheck;
				case 'd':
					switch(len) {
						case _SHORT:
							itoa(buf,c,(uint64)va_arg(ap, int), pad, len);
							break;
						case _INT:
							itoa(buf,c,(uint64)va_arg(ap, int32), pad, len);
							break;
						case _LONG:
							itoa(buf,c,(uint64)va_arg(ap, int64), pad, len);
							break;
					}
	
padcheck:
					if(pad) 
						for(i=0,l=(len<<2)-strlen(buf) ; l && i < l ; i++)
							puts("0");
					len = _INT;
					pad = false;
					goto string;
				case 's':
					p = va_arg(ap, char *);
string:
					if(!p) puts("(null)");
					else if(*p) con_write(NULL, (uint8 *)p, strlen(p));
					break;
				case 'c':
					c = va_arg(ap, int);
					if(c>=' ' && c<='~') 
						putsn(&c, 1);
					break;
			}
		}
	}
}

void printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}


int putsn(char *text, size_t max)
{
	//char *tmp = text;
	//int cnt = 0;

	return con_write(NULL, (uint8 *)text, (uint64)max);
}

int puts(char *text)
{
	return putsn(text, strlen(text));
}

bool isprint(uint8 c)
{
	return (c>31 && c<177) ? true : false;
}

void *memcpy(void *dest, void *src, size_t count)
{
	char *sp = (char *)src;
	char *dp = (char *)dest;

	if(!count || !dest || !src || !is_valid(sp) || !is_valid(dp)) return NULL;

	for(; count !=0; count--) *dp++ = *sp++;

	return dest;
}

void *memset(void *dest, int val, size_t count)
{
	unsigned char *temp = (unsigned char *)dest;
	uint64 cnt;

	for(cnt = count; cnt; cnt--) {
		*temp++ = (unsigned char)val;
	}
	return dest;
}

char *strcpy(char *dest, const char *src)
{
	return strncpy(dest, src, strlen(src));
}

char *strncpy(char *dest, const char *source, unsigned long count)
{
	char *dst = (char *)dest;
	const char *src = (const char *)source;


	for(; (count!=0) && *src!='\0'; count--) *dst++ = *src++;
	return dest;
}

short *memsetw(short *dest, unsigned short val, uint64 count)
{
	unsigned short *temp;
	temp = (unsigned short *)dest;


	for(; count != 0; count--) *temp++ = val;
	return dest;
}

uint64 strlen(const char *str)
{
	int retval;
	for(retval=0; *str != '\0'; str++) retval++;
	return retval;
}

uint64 strcmp(const char *a, const char *b)
{
	return(strncmp(a,b,0));
}

uint64 strncmp(const char *a, const char *b, uint64 len)
{
	if(!len) {
		if(strlen(a) != strlen(b)) return 1;
		len = strlen(a);
	}

	while(len)
	{
		if(a[len] != b[len]) return 1;
		len--;
	}


	return 0;
}

uint16 htons(uint16 word)
{
	uint8 *s = (uint8 *)&word;
	return (uint16)(s[0]<<8|s[1]);
}

uint32 htonl(uint32 word)
{
	uint8 *s = (uint8 *)&word;
	return (uint32)(s[0]<<24|s[1]<<16|s[2]<<8|s[3]);
}

uint64 htonq(uint64 word)
{
	//uint8 *s = (uint8 *)&word;
	return (uint64)(0);
}

uint16 ntohs(uint16 word)
{
	uint8 *s = (uint8 *)&word;
	return (uint16)(s[0]<<8|s[1]);
}

uint32 ntohl(uint32 word)
{
	uint8 *s = (uint8 *)&word;
	return (uint32)(s[0]<<24|s[1]<<16|s[2]<<8|s[3]);
}

void print_bits(uint64 val, const char *bits[], uint64 max, uint8 br)
{
	int off;
	int first = 0;

	if(!max || max > 64) return;

	for(off = 0 ; off < max ; off++)
	{
		if(!bits[off]) break;
		if(val & (1<< off)) {
			if(first && br) printf("%c",br);
			printf("%s", bits[off]);
			first = 1;
		} else if(!br) {
			printf("-");
		}
	}
}
