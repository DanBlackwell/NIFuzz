/// Harness

#include "memory.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

unsigned int target_func(unsigned int public, unsigned int secret) {
  if (public % 4 == 0)
    return secret % 4;
  else
    return public % 4;
}

__AFL_FUZZ_INIT();

int main(int argc, char **argv) 
{
  __AFL_INIT();

  // handle PUBLIC

  static unsigned int public, secret;
  if (EXPLICIT_PUBLIC_LEN < sizeof(public)) { return 1; }

  public = *(unsigned int *)EXPLICIT_PUBLIC_IN;

  // handle SECRET
  if (EXPLICIT_SECRET_LEN < sizeof(secret)) { return 1; }
  secret = *(unsigned int *)EXPLICIT_SECRET_IN;
  initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);
  FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);

  // execute the function
  unsigned int res = target_func(public, secret); 
  printf("Result: %u\n", res);

  return 0;
}
