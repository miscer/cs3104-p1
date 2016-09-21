/*	Stuart Norcross - 12/03/10 */

/* This program allocates integer arrays and displays trace information*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "myalloc.h"

#define INTS_PER_ALLOCATION 10

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
	void *p0 = alloc_and_set(-1);printf("TEST 0 PASSED - ALLOCATED (WILL NOT BE FREED)\n");
	check(p0,-1);
	
	// allocate
	void *p1 = alloc_and_set(1);printf("TEST 1 PASSED - ALLOCATED\n");
	check(p1,1);
	
	
	//free
	myfree(p1);
	printf("TEST 2 PASSED - FREED\n");
	
	//allocate
	void *p2 = alloc_and_set(2);
	check(p2,2);
	
	//p1 and p2 should be the same
	if(p1==p2)printf("TEST 3 PASSED - P1 EQUALS P2\n");
	else printf("TEST 3 FAILED - P1 NOT EQUAL TO P2\n");
		
	myfree(p2);
	
	void *p3 = alloc_and_set(3);
	check(p3,3);
	printf("TEST 4 PASSED - ALLOCATED\n");
	void *p4 = alloc_and_set(4);
	check(p4,4);
	printf("TEST 5 PASSED - ALLOCATED\n");
	
	myfree(p3);
	printf("TEST 6 PASSED - FREED\n");
	myfree(p4);
	printf("TEST 7 PASSED - FREED\n");

	printf("%s complete\n",argv[0]);
	
}
