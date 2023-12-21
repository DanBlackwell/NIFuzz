/// Harness

#include "memory.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

struct __attribute__ ((__packed__)) leaky {
  unsigned int start;
  unsigned char leak[601]; // 601 is prime
  unsigned int end;
};

void target_func(unsigned int start, unsigned int end, struct leaky *out) {
  struct leaky *res = malloc(sizeof(struct leaky));

  res->start = start;
  res->end = end;
  memcpy(out, res, sizeof(*res));
  free(res);
}

__AFL_FUZZ_INIT();

int main(int argc, char **argv) 
{
  __AFL_INIT();

  // handle PUBLIC

  static int start, end;
  if (EXPLICIT_PUBLIC_LEN < sizeof(start) + sizeof(end)) { return 1; }

  start = *(unsigned int *)EXPLICIT_PUBLIC_IN;
  end = *(unsigned int *)(EXPLICIT_PUBLIC_IN + sizeof(start));

  // handle SECRET
  initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);
  FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);

  // execute the function
  static struct leaky res = {0};
  target_func(start, end, &res); 
  write(1, &res, sizeof(res));
  fflush(stdout);

  return 0;
}
