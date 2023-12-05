#include "getsockopt.c"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define INIT_INPUT(num)
#define GENERATE_OUTPUT(num) int res ## num = 0; \
  char optname ## num; \
  char optval ## num[80] = {0}; \
  int optlen ## num = 0; \
  res ## num = sco_sock_getsockopt_old(&socket, optname ## num, optval ## num, &optlen ## num);
#define OUTPUTS_EQUAL(out1, out2) (res ## out1 == res ## out2 && optlen ## out1 == optlen ## out2 && !memcmp(optval ## out1, optval ## out2, optlen ## out1))

int main(void) 
{
  struct sock mySock;
  struct socket mySocket = { .sk = &mySock };
  char optname;
  char optval[80] = {0};
  int optlen = 0;

  CHECK_LEAKAGE();
}
