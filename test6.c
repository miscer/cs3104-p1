#include <stdio.h>
#include <unistd.h>
#include "myalloc.h"

int main() {
  myalloc(10);

  int size = (1 << 18);
  void *ptr = myalloc(size);

  int *start = ptr;
  int *end = ptr + size;
  int *last = end - 1;

  *start = 1;
  *last = 2;

  myfree(ptr);

  printf("should segfault now\n");
  *start = 1;
}
