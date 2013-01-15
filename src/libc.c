#include "libc.h"

extern FILE *stdin, *stdout, *stderr;

int brk(void *addr)
{
	return (int)SYSCALL1(SYSCALL_BRK, addr);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	if(fd == -1) return -EBADF;
	if(!buf) return -EFAULT;
	if(!count) return 0;

	return (ssize_t)SYSCALL3(SYSCALL_WRITE, fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret;

	if(fd == -1) return -EBADF;
	if(!buf) return -EFAULT;
	if(!count) return 0;

	ret = (size_t)SYSCALL3(SYSCALL_READ, fd, buf, count);

	return ret;
}

int open(const char *pathname, int flags)
{
	return (int)SYSCALL2(SYSCALL_OPEN, pathname, flags);
}

void *memset(void *dest, unsigned char val, size_t count)
{
	unsigned char *temp = (unsigned char *)dest;
	unsigned long c = count;
	for(; c; c--) *temp++ = val;
	return dest;
}

size_t strlen(const char *str)
{
	size_t retval;
	for(retval=0; *str != '\0'; str++) retval++;
	return retval;
}


void itoa (char *buf, int base, unsigned long d, bool pad, int size)
{
	char *p = buf, *p1, *p2;
	unsigned long ud = d;
	unsigned long divisor = 10;
	unsigned long remainder;

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

int fputc(int c, FILE *s)
{
	int r;

	if(!s) return EOF;
	if(s->fd == -1) return EOF;
	if((r = write(s->fd, &c, 1)) != 1) return EOF;
	return r;
}

int fgetc(FILE *s)
{
	int r;

	if(!s) return EOF;
	if(s->fd == -1) return EOF;
	while(read(s->fd, &r, 1) == 0) ;
	return r;
}

int putchar(int c)
{
	return fputc(c, stdout);
}

int getchar(void)
{
	return fgetc(stdin);
}

int fputs(const char *c, FILE *s)
{
	ssize_t ret;

	if(!s || !c) return EOF;
	if(s->fd == -1) return EOF;

	ret = write(s->fd, c, strlen(c));

	if(ret < 0) return EOF; 
	else return ret;
}

void vfprintf(FILE *f, const char *format, va_list ap)
{
	char c;
	char *p;
	char buf[64],buf2[64];
	bool lng = false;
	bool pad = false;

	memset(buf2, '0', 63); buf[63] = '\0';

	while ((c = *format++) != 0)
	{
		if ( c!= '%' ) {
			fputc(c, f);
		} else {
next:
			c = *format++;
			p = buf;
			switch(c)
			{
				case '0':
					pad = true;
					goto next;
				case 'l':
					lng = true;
					goto next;
				case 'd':
				case 'u':
				case 'x':
					if(lng)
						itoa(buf,c,(unsigned long)va_arg(ap, unsigned long), pad, 8);
					else
						itoa(buf,c,(unsigned long)va_arg(ap, unsigned int), pad, 4);
					if(pad)
						for(int i=0,l=(lng ? 16 : 8) - strlen(buf) ;
								l && i < l ;
								i++)
							fputc('0', f);
					lng = pad = false;
					goto string;
				case 's':
					p = va_arg(ap, char *);
string:
					if(!p) fputs("(null)", f);
					else if(*p) fputs(p, f);
					break;
				case 'c':
					c = va_arg(ap, int);
					if(c>=' ' && c<='~') {
						fputc((char)c, f);
					}
					break;
			}
		}
	}
}

void vprintf(const char *format, va_list ap)
{
	vfprintf(stdout, format, ap);
}

void printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

void fprintf(FILE *fp, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(fp, format, ap);
	va_end(ap);
}


pid_t getpid(void)
{
	return (pid_t)SYSCALL0(SYSCALL_GETPID);
}

pid_t fork(void)
{
	return (pid_t)SYSCALL0(SYSCALL_FORK);
}

void exit(int status)
{
	SYSCALL1(SYSCALL_EXIT, status);
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	if(!status) return -EINVAL;
	return (pid_t)SYSCALL4(SYSCALL_WAIT4, pid, status, options, rusage);
}

pid_t wait(int *status)
{
	return wait4(-1, status, 0, NULL);
}

int execve(const char *file, char *const argv[], char *const envp[])
{
	return (int)SYSCALL3(SYSCALL_EXECVE, file, argv, envp);
}

int execvp(const char *file, char *const argv[])
{
	return execve(file, argv, NULL);
}
