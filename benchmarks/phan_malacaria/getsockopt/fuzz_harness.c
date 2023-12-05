#include "getsockopt.c"

#include "memory.h"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

__AFL_FUZZ_INIT();

int main(void) 
{
  __AFL_INIT();

  // handle SECRET

  initMemFillBuf(SECRET_IN, SECRET_LEN);
  enableMemWrap();
  
  // handle PUBLIC
  
  if (PUBLIC_LEN < sizeof(struct sock) + 1) return 1;

  static struct sock mySock;
  memcpy(&mySock, PUBLIC_IN, sizeof(mySock));
  static struct socket mySocket = {0};
  mySocket.sk = &mySock;
  static char optname; optname = *(PUBLIC_IN + sizeof(mySock));
  static char optval[80];
  static int optlen = sizeof(optval);
  
  FILL_STACK(SECRET_IN, SECRET_LEN);
  static int res;
  res = sco_sock_getsockopt_old(&mySocket, optname, optval, &optlen);
  write(1, &res, sizeof(res));
  write(1, optval, optlen);
}
