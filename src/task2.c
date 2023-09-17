#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>

int function(int a)
{
	int b = a++;
	return b;
}

int main(void)
{
//	int status;
//	pid_t pid;

	printf("\nFailOS\n");

	//uint64 fsbase, gsbase, fsreg;

	//__asm__ volatile("rdgsbase %0":"=r"(gsbase));
	//__asm__ volatile("rdfsbase %0":"=r"(fsbase));
	//__asm__ volatile("movq %%fs, %0":"=r"(fsreg));
	//printf("1:gsbase = %lx, fsbase = %lx, fsreg = %lx\n", gsbase, fsbase, fsreg);

	int pid;

	/*
	if((pid = fork())) {
	//	execvp("/task3", NULL);
		printf("\n*** Done. Parent: Pid1=%lx\n", pid);
		if((pid = fork())) {
			printf("\n *** Done. Parent: Pid2=%lx\n", pid);
			int d = 0;
			while(1) { d++; printf("%d", getpid()); }
		} else {
			printf("\n *** Done. Child1\n");
			int a = 0;
			while(1) { a++; printf("%d", getpid()); }
		}
	} else {
		printf("\n *** Done. Child2\n");
		int c = 0;
		while(1) { c++; printf("%d", getpid()); }
	}*/

	int children = 0;
	
	//syscall(100);

	//int i = 0;

	//while(i++ < 1000000) __asm__ volatile ("pause;");

//	if(getpid()==1)
//		syscall(60);
//	else
//		exit(0);

	if(getpid() != 1)
	{

//#define DO_FORK
#ifdef DO_FORK
		while(getpid() < 5) {
			printf("%d: forking\n", getpid());
			if ( (pid = fork()) ) {
				children++;
				int b = 1;
				//while(b++ < 1000) ;
				//uint64 fsbase, gsbase;
				printf("%d: fork %d\n", getpid(), pid);
				//__asm__ volatile("xchg %%bx,%%bx":::"rbx");

				while(1) { 
					b++;
					if(!(b % 2000)) {
						//uint64 rsp,rspval;
						//__asm__ volatile("mov %%rsp, %0":"=m"(rsp));
						//__asm__ volatile("movq (%%rsp), %0":"=r"(rspval));
						//printf("rsp=%lx rspval=%lx\n", rsp, rspval);
						//if(b>1) {
						//__asm__ volatile("xchg %%bx,%%bx":::"rbx");
						function(b);
						//SYSCALL0(100);
						//__asm__ volatile("rdgsbase %0":"=r"(gsbase));
						//__asm__ volatile("rdfsbase %0":"=r"(fsbase));
						//printf("1:gsbase = %lx, fsbase = %lx\n", gsbase, fsbase);
						//}
					}
				}
			} else
				printf("%d: fork %d\n", getpid(), pid);
		}
		while(1) __asm__ volatile( "pause" );
#else
		/*
		int a = 0;
		while(1) {
			a++;
			if(!(a % 2000000)) {
				SYSCALL0(100);
				//__asm__ volatile("rdgsbase %0":"=r"(gsbase));
				//__asm__ volatile("rdfsbase %0":"=r"(fsbase));
				//printf("2:gsbase = %lx, fsbase = %lx\n", gsbase, fsbase);
			}
		}*/
#endif
	}
	//printf("%d: pausing\n", getpid());
	//while(1) {
	//	SYSCALL0(100);
	//	__asm__ volatile("pause");
	//}

	unsigned long pos = 0;
	char buf[50];
	memset(buf, 0, sizeof(buf));

	printf("\n%d # ", getpid());

	while(1)
	{
		int c = getchar();
		putchar(c);

		if(c == '\b' && pos > 0) {
			buf[pos]   = 0;
			buf[--pos] = 0;
		} else if(c == '\r') {
			buf[pos]   = 0;
			pos = 0;

			//printf("\nYour command was: '%s'", buf);

			if(buf[0] == 'f') {
				if((pid = fork())) {
					printf("Done. Parent: %lx\n", pid);
				} else {
					printf("Done. Child: %lx\n", pid);
					execve("/java", (char *[]){"/java","Empty",NULL}, (char *[]){NULL});
					//execve("/init", NULL, NULL);
					while(1) ;
				}

			} else if(buf[0] == 'e') {
				exit(EXIT_SUCCESS);
			} else {
				system(buf);
			}
			memset(buf, 0, sizeof(buf));

			printf("\n%d # ", getpid());
		} else {
			if(pos < (sizeof(buf)-1)) {
				buf[pos++] = (char)c;
				buf[pos]   = 0;
			}
		}

		//printf("pos=%d buf='%s'\n", pos, buf);
	}
	while(1) __asm__("pause");
}
