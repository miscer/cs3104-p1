/*	Stuart Norcross - 12/03/10 */

/* This program allocates integer arrays and displays trace information*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "myalloc.h"

#define NUMBER_OF_ALLOCATIONS 100
#define INTS_PER_ALLOCATION 1000

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
	int *allocated[NUMBER_OF_ALLOCATIONS];
	int i;
	printf("%s starting\n",argv[0]);
	
	// do some allocation
	for(i=0;i<NUMBER_OF_ALLOCATIONS;i++){
		allocated[i]=alloc_and_set(i);
	}
	
	// check the allocations.
	for(i=0;i<NUMBER_OF_ALLOCATIONS;i++){
		check(allocated[i],i);
	}
	sleep(1);
	// free the first, 10th and 20th allocations.
	myfree(allocated[0]);
	myfree(allocated[9]);
	myfree(allocated[19]);
	
	// more allocations
	allocated[0]=alloc_and_set(9999999);
	allocated[9]=alloc_and_set(9999998);
	allocated[19]=alloc_and_set(9999997);
	
		//check the latest allocations
	check(allocated[0],9999999);
	check(allocated[9],9999998);
	check(allocated[19],9999997);
	
	// check the rest of the allocations
	for(i=0;i<NUMBER_OF_ALLOCATIONS;i++){
		if(i!=0&&i!=9&&i!=19)	check(allocated[i],i);
	}
	
	printf("%s complete\n",argv[0]);
	
}
