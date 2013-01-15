#include "libc.h"

int main(int, char **);

FILE *stdin, *stdout, *stderr;

void _start()
{
	void *tmp = (void *)(unsigned long)brk(0);
	brk(tmp + 0x100000);

	stdin = tmp;
	stdout = stdin + sizeof(FILE);
	stderr = stdout + sizeof(FILE);

	stdin->fd = open("/dev/tty", O_RDONLY);
	stdout->fd = open("/dev/tty", O_WRONLY);
	stderr->fd = open("/dev/tty", O_WRONLY);

	main(0, 0);
}
