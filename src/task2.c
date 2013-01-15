#include "syscall.h"
#include "libc.h"

#define AF_INET	2
#define	SOCK_STREAM	1

typedef	unsigned short	uint16;
typedef	unsigned int	uint32;
typedef	unsigned long	uint64;

struct in_addr {
	uint32 s_addr;
};

#define INADDR_ANY      ((uint32)0x0)

struct sockaddr;

struct sockaddr_in {
	uint16  sin_family;
	uint16  sin_port;
	struct in_addr sin_addr;
};


void crap(void);

extern unsigned long _end;

const char *name = "/dev/hd0";

void main(int ac, char *av[])
{
	int pos = 0;
	char buf[50];
	int status;
	pid_t pid;

	printf("FailOS: pid=%x\n", getpid());

	printf("# ");

	/*
	while(1)
	{
		int c = getchar();
		putchar(c);
		if(c == '\b') {
			buf[--pos]='\0';
		} else if(c == '\r') {
			buf[pos]='\0';
			printf("\nYour command was: '%s'", buf);
			printf("\n# ");
			pos = 0;
			if(buf[0] == 'f') {*/
				if(!fork()) {
					printf("Sleeping\n");
					while(1) ;
				} else {
					//execvp("/init", NULL);
					while(1) ;
				}/*
			} else if(buf[0] == 'e') {
				exit(EXIT_SUCCESS);
			}
		} else {
			if(pos < 50) buf[pos++] = (char)c;
		}
	}
	*/
	while(1) ; 
}
