/// Harness

#include "memory.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) 
{
  __AFL_INIT();

  // handle SECRET
  
  if (EXPLICIT_SECRET_LEN < 1) { return 1; }
  initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);
  FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);

  static int pos = 0;
  static int bytes = 0, bits = 0;
  static unsigned mask = 0;
  static unsigned char last_bits = 0;
  while (pos < 701) {
    if (701 - pos >= 8 * EXPLICIT_SECRET_LEN) {
      write(1, EXPLICIT_SECRET_IN, EXPLICIT_SECRET_LEN);
      pos += 8 * EXPLICIT_SECRET_LEN;
    } else {
      bytes = (701 - pos) / 8;
      write(1, EXPLICIT_SECRET_IN, bytes);
      bits = 701 - 8 * bytes;
      mask = (1 << bits) - 1;
      last_bits = (unsigned char)mask & *(EXPLICIT_SECRET_IN + bytes);
      write(1, &last_bits, 1); 
      break;
    }
  }
  fflush(stdout);

  return 0;
}
