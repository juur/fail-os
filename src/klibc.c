#define _LIBC_C
#include <klibc.h>
#include <dev.h>
#include <mem.h>

__attribute__((nonnull))
static void itoa (char *const buffer, const int base, const uint64_t d, const bool pad, const int size)
{
	char *buf = buffer;
	char *p = buf, *p1, *p2;
	uint64_t ud = d;
	uint64_t divisor = 10;
	uint64_t remainder;

	if(pad)
		for(int tmp = 0; tmp < size; tmp++)
			buf[tmp] = '0';

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

static const char zeros[] = "0000000000000000";

__attribute__((nonnull))
static int vprintf(const char *const fmt, va_list ap)
{
	char c;
	const char *p;
	const char *format = fmt;
	char buf[64]={0};//,buf2[64]={0};
	int len = _INT;
	int padcnt = 0;
	bool pad = false;
	//int i,l;

	//memset(buf2, '0', sizeof(buf2));
	//memset(buf,  '0', sizeof(buf));

	//if (!is_valid((uint8_t *)format))
	//	return -1;

	while ((c = *format++) != 0)
	{
		if ( c!= '%' ) {
			putsn(&c, 1); 
		} else {
next:
			c = *format++;
			p = buf;
			if(isdigit(c) && !(padcnt == 0 && c == '0')) {
				padcnt *= 10;
				padcnt += c - '0';
				goto next;
			} else
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
							itoa(buf,c,(uint64_t)va_arg(ap, unsigned int), pad, len);
							break;
						case _INT:
							itoa(buf,c,(uint64_t)va_arg(ap, unsigned int), pad, len);
							break;
						case _LONG:
							itoa(buf,c,(uint64_t)va_arg(ap, unsigned long), pad, len);
							break;
					}
					goto padcheck;
				case 'd':
					switch(len) {
						case _SHORT:
							itoa(buf,c,(uint64_t)va_arg(ap, int), pad, len);
							break;
						case _INT:
							itoa(buf,c,(uint64_t)va_arg(ap, int), pad, len);
							break;
						case _LONG:
							itoa(buf,c,(uint64_t)va_arg(ap, long), pad, len);
							break;
					}
	
padcheck:
					if(pad) {
//						for(i=0,l=(len<<2)-strlen(buf) ; l && i < l ; i++)
						int l = ((padcnt ? (int)padcnt : len*2)) - strlen(buf);
						if(l)
							putsn(zeros, l);
						padcnt = 0;
					}
					len = _INT;
					pad = false;
					goto string;
				case 's':
					p = va_arg(ap, const char *);
string:
					if(!p) putsn("(null)",6);
					else if(*p) {
						putsn(p, strlen(p));

						if(padcnt && (int)strlen(p) < padcnt)
							for(padcnt = (padcnt - strlen(p)); padcnt; padcnt--)
								putsn(" ",1);
					}
					padcnt = 0;
					break;
				case 'c':
					c = va_arg(ap, int);
					if(c>=' ' && c<='~') 
						putsn(&c, 1);
					break;
			}
		}
	}

	return 0;
}

int printf(const char *const format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	return 0;
}

extern struct char_dev *con_dev;

int putsn(const char *const text, const size_t max)
{
	//char *tmp = text;
	//int cnt = 0;
	return con_write(con_dev, text, (uint64_t)max);
}

int puts(const char *const text)
{
	return putsn(text, strlen(text));
}

int isprint(int ch)
{
	unsigned char c = (unsigned char)ch;
	return (c>31 && c<177) ? true : false;
}

#define ULLONG_SIZE sizeof(unsigned long long)

void *_memcpy(void *const dest, const void *const src, size_t cnt,
        const char *file, const char *func, int line)
{
	register size_t todo = cnt;
	register const unsigned long long *restrict src_ptr;
	register unsigned long long *restrict dst_ptr;
	const unsigned char *restrict s_ptr;
	unsigned char *d_ptr;

    //printf("memcpy: (%p, %p, %lu): %s:%s:%d\n",
    //        dest, src, cnt, file, func, line);

	s_ptr = src;
	d_ptr = dest;

	src_ptr = src;
	dst_ptr = dest;

	if (todo > ULLONG_SIZE) {
		for (;todo > ULLONG_SIZE; todo -= ULLONG_SIZE)
			*(dst_ptr++) = *(src_ptr++);

		s_ptr += (cnt - todo);
		d_ptr += (cnt - todo);
	}

	for (size_t i = 0; i < todo; i++)
		*(d_ptr++) = *(s_ptr++);

	return dest;
}

#undef ULLONG_SIZE

void *memset(void *dest, int val, size_t count)
{
	uint8_t volatile *temp = dest;
    const uint8_t _val = (uint8_t)val;
    size_t cnt;

	if(!count || !is_valid(dest))
        return NULL;

	for(cnt = count; cnt; cnt--)
		*(temp++) = _val;

	return dest;
}

char *strcpy(char *const dest, const char *const src)
{
	return strncpy(dest, src, strlen(src));
}

char *strncpy(char *const dest, const char *const source, const unsigned long cnt)
{
	char *dst = dest;
	const char *src = source;
	uint64_t count = cnt;

	for(; count && *src!='\0'; count--) *dst++ = *src++;
	
	if(count == 0)
		*dst = '\0';

	return dest;
}

char *strdup(const char *const s)
{
	const size_t len = strlen(s) + 1;
	char *ret = kmalloc(len, "strdup", NULL, KMF_ZERO);
	if (ret)
		memcpy(ret, s, len);
	return ret;
}

char *basename(const char *path)
{
	size_t len = strlen(path);

	if(!len)
		return(strdup(path));

	const char *const end = (path + len - 1);
	const char *src = end;

	while(*src && src >= path && *src != '/')
		src--;

	if(src == path)
		return(strdup(path));

	src++;
	const size_t nlen = end - src + 1;

	char *ret;
	if((ret = kmalloc(nlen + 1, "basename", NULL, KMF_ZERO)) == NULL)
		return NULL;

	memcpy(ret, src, nlen);

	return ret;
}

char *dirname(const char *path)
{
	size_t len = strlen(path);

	if (!len)
		return strdup("");

	const char *const end = (path + len - 1);
	const char *src = end;

	while(*src && src >= path && *src != '/') {
		src--;
	}

	if(src == path)
		return(strdup("."));

	size_t nlen = src - path + 1;

	char *ret;
	if((ret = kmalloc(nlen, "dirname", NULL, KMF_ZERO)) == NULL)
		return NULL;

	memcpy(ret, path, nlen - 1);

	return ret;
}


size_t strlen(const char *const string)
{
	int retval;
	const char *str = string;

	for(retval=0; *str != '\0'; str++) retval++;
	return retval;
}

size_t strnlen(const char *const s, const size_t maxlen)
{
	size_t len = 0;
	const char *str = s;

	for(;*str && len < maxlen; str++, len++) ;

	return len;
}

int strcmp(const char *const a, const char *const b)
{
	return(strncmp(a,b,0));
}

int popcountll(unsigned long long x)
{
  // Binary: 0101...
  static const unsigned long long m1 = 0x5555555555555555;
  // Binary: 00110011..
  static const unsigned long long m2 = 0x3333333333333333;
  // Binary:  4 zeros,  4 ones ...
  static const unsigned long long m4 = 0x0f0f0f0f0f0f0f0f;
  // The sum of 256 to the power of 0,1,2,3...
  static const unsigned long long h01 = 0x0101010101010101;
  // Put count of each 2 bits into those 2 bits.
  x -= (x >> 1) & m1;
  // Put count of each 4 bits into those 4 bits.
  x = (x & m2) + ((x >> 2) & m2);
  // Put count of each 8 bits into those 8 bits.
  x = (x + (x >> 4)) & m4;
  // Returns left 8 bits of x + (x<<8) + (x<<16) + (x<<24) + ...
  return (int)((x * h01) >> 56);
}

char *strchr(const char *const s, const int c)
{
	const char *tmp;

	for(tmp = s; *tmp && *tmp != c; tmp++) ;
	if(!*tmp) return NULL;
	return (char *)tmp;
}

static const char *const error_strings[] = {
	"unknown", // 0
	"EPERM",
	"ENOENT",
	"ESRCH",
	"EINTR",
	"EIO",
	"ENXIO",
	"E2BIG",
	"ENOEXEC",
	"EBADF",
	"ECHILD",
	"EAGAIN",
	"ENOMEM", // 12
	"EACCES",
	"EFAULT",
	"ENOTBLK",
	"EBUSY",
	"EEXIST",
	"EXDEV",
	"ENODEV",
	"ENOTDIR",
	"EISDIR",
	"EINVAL",
	"ENFILE",
	"EMFILE",
	"ENOTTY", // 25
	"ETXTBSY",
	"EFBIG",
	"ENOSPC",
	"ESPIPE",
	"EROFS",
	"EMLINK",
	"EPIPE",
	"EDOM",
	"ERANGE", // 34
	"EDEADLK",
	"ENAMETOOLONG",
	"ENOLCK",
	"ENOSYS",
	"ENOTEMPTY",
	"ELOOP",
	NULL
};
static const int error_strings_len = sizeof(error_strings) / sizeof(error_strings[0]) - 1;

const char *strerror(int ec)
{
	if (ec < 0) ec = -ec;

	if(ec <= 0 || ec > error_strings_len || error_strings[ec] == NULL)
		return "unknown";
	return error_strings[ec];
}

char *strtok_r(char *const str, const char *const delim, char **saveptr)
{
	char *tmp, *ret;

	if(str)
		*saveptr = str;

	if(!*saveptr)
		return NULL;

	while(**saveptr && *(*saveptr+1) && strchr(delim, **saveptr))
		*(*saveptr)++ = '\0';

	tmp = *saveptr;

	while(*tmp && !strchr(delim, *tmp))
		tmp++;

	while(*tmp && *(tmp+1) && strchr(delim, *(tmp+1)))
		*tmp++ = '\0';

	if(tmp == *saveptr)
		return (*saveptr = NULL);

	if(!*tmp) {
		ret = *saveptr;
		*saveptr = NULL;
		return ret;
	}

	*tmp = '\0';
	ret = *saveptr;

	*saveptr = ++tmp;
	return ret;
}

__attribute__((nonnull))
int strncmp(const char *const a, const char *const b, const uint64_t length)
{
	uint64_t cnt = 0;
	uint64_t len = length;

	if(!len) {
		if(strlen(a) != strlen(b)) return 1;
		len = strlen(a);
	}

	while(cnt<len)
	{
		if(a[cnt] != b[cnt]) { return 1; };
		if(!a[cnt] && !b[cnt]) return 0;
		if(!a[cnt] || !b[cnt]) { return 1; };
		cnt++;
	}
	return 0;
}

uint16_t htons(uint16_t word)
{
	uint8_t *s = (uint8_t *)&word;
	return (uint16_t)(s[0]<<8|s[1]);
}

uint32_t htonl(uint32_t word)
{
	uint8_t *s = (uint8_t *)&word;
	return (uint32_t)(s[0]<<24|s[1]<<16|s[2]<<8|s[3]);
}

/*
uint64_t htonq(uint64_t word)
{
	//uint8_t *s = (uint8_t *)&word;
	return (uint64_t)(0);
}
*/

uint16_t ntohs(uint16_t word)
{
	uint8_t *s = (uint8_t *)&word;
	return (uint16_t)(s[0]<<8|s[1]);
}

uint32_t ntohl(uint32_t word)
{
	uint8_t *s = (uint8_t *)&word;
	return (uint32_t)(s[0]<<24|s[1]<<16|s[2]<<8|s[3]);
}

void print_bits(uint64_t val, const char *bits[], uint64_t max, uint8_t br)
{
	uint64_t off;
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

int isdigit(int c)
{
	if((char)c >= '0' && (char)c <= '9')
		return 1;
	return 0;
}
