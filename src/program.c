#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The following line is needed for shared memory testcase fuzzing
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
  // Start the forkserver at this point (i.e., forks will happen here)
  __AFL_INIT();

  // The following five lines are for normal fuzzing.
  /*
  FILE *file = stdin;
  if (argc > 1) { file = fopen(argv[1], "rb"); }
  char  buf[16];
  char *p = fgets(buf, 16, file);
  buf[15] = 0;
  */

  // The following line is also needed for shared memory testcase fuzzing
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT

//  if (__AFL_FUZZ_TESTCASE_LEN == 8) {
//    printf("8 bytes: [%u, %u]\n", *(unsigned *)buf, *(unsigned *)(buf + 4));
//  }
  unsigned int len = __AFL_FUZZ_TESTCASE_LEN;
  unsigned int public_len = *(unsigned int *)buf;
  unsigned int secret_len = len - public_len - sizeof(public_len);
  unsigned char *public_buf = buf + sizeof(public_len);
  unsigned char *secret_buf = public_buf + public_len;
  // printf("total len: %u, public: %u, secret:%u\n", len, public_len, secret_len);

//  if (secret_len == 1 || public_len > 1) abort();

//  if (!memcmp(secret_buf, "W0", 1)) {
//    printf("Found it!\n");
//  }

  if (secret_len > 1) {
    printf("%c%c", secret_buf[1], (char)(secret_buf[2] & 0xF0));
  }

  if (secret_len > 3) {
    printf("%c", secret_buf[3] & 0x4);
  }
  printf("\n");

//   printf("input: %s\n", buf);
  if (public_buf[0] == 'b') {
    if (public_buf[1] == 'a') {
      if (public_buf[2] == 'd') { abort(); }
    }
  }
//  vuln((char *)public_buf);

  return 0;
}
