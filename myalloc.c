/*	Stuart Norcross - 12/03/10 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

#include "myalloc.h"



void *myalloc(int size){
	void *newRegion = malloc(size);
	return newRegion;
}

void myfree(void *ptr){
	free(ptr);
}
