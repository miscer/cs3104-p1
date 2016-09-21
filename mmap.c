#include <sys/mman.h>
#include <stdio.h>

main(){
	int size=10<<10; //10kB, (3 pages)
	printf("My pid is %i\n", getpid());
  	void *pg_addr = 0x00007f5b613d1000;
	printf("sizeof(pg_addr) = %i\n",sizeof(pg_addr));
   	//pg_addr = mmap(0,size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,0, 0);
 	printf("mapped address is %.16p\n", pg_addr);
	*((int*)pg_addr)=0xdeadbeef; //write something
	while(1);
}

