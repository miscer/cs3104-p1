#include <stdio.h>
#include <assert.h>
#include "myalloc.h"

int main() {
  void* first_large = myalloc(100);
  void* second_large = myalloc(100);

  myfree(first_large);

  void* first_small = myalloc(10);
  void* second_small = myalloc(10);

  assert(first_small < second_large);
  assert(second_small < second_large);

  myfree(first_small);
  myfree(second_small);

  void* third_large = myalloc(100);
  assert(first_large == third_large);
}
