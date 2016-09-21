/*	Stuart Norcross - 12/03/10 */

/* This program allocates integer arrays and displays trace information*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "myalloc.h"

#define INTS_PER_ALLOCATION 4000000

int alloc_size=sizeof(int)*INTS_PER_ALLOCATION;

void check_failed(int val){
	fprintf(stderr, "Check failed for region with value %i.",val);
	exit(-1);
}

void check(int *mem, int value){
	int i;
	for(i=0;i<INTS_PER_ALLOCATION;i++){
		if(mem[i]!=value)check_failed(value);
	}
}

void set(int *mem, int value){
	int i;
	for(i=0;i<INTS_PER_ALLOCATION;i++){
		mem[i]=value;
	}
}

int *alloc_and_set(int value){
	int* mem = (int*)myalloc(alloc_size);
	set(mem,value);
	return mem;
}

int main(int argc, char* argv[]){
	printf("%s starting\n",argv[0]);

	// allocate
	printf("TRYING TO ALLOCATE %i BYTES\n",alloc_size);
	void *p1 = alloc_and_set(1);
	check(p1,1);
	
	printf("TEST 1 PASSED - ALLOCATED %i BYTES\n",alloc_size);

	printf("%s complete\n",argv[0]);
	
}
