#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>

main(){
	int size=10<<10; //10kB, (3 pages)
	printf("My pid is %i\n", getpid());
   	void *pg_addr = mmap(0,size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1, 0);
 	printf("mapped address is %.16p\n", pg_addr);
	*((int*)pg_addr)=0xdeadbeef; //write something
	printf("sizeof(void *) = %i\n", sizeof(pg_addr));
	printf("sizeof(int) = %i\n", sizeof(int));
	printf("sizeof(long) = %i\n", sizeof(long));
	
	void *ptr = (void *) ((uintptr_t) pg_addr & ~(uintptr_t) 0xffff);
	printf("mapped address is %.16p\n", ptr);

	while(1);
}

