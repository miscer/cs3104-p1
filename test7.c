#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include "myalloc.h"

int main() {
  int* mem[4];

  size_t value = 1024;

  for (int i = 0; i < 4; i++) {
    mem[i] = myalloc(sizeof(size_t));
    *mem[i] = value;
  }

  for (int i = 0; i < 4; i++) {
    assert(*mem[i] == value);
  }
}
