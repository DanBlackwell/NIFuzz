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

  initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);
  FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);
  
  // handle PUBLIC
  
  if (EXPLICIT_PUBLIC_LEN < sizeof(struct hci_conn) + sizeof(struct sco_conn) + sizeof(struct sco_pinfo) + 1) {
    return 1;
  }

  // static struct sock mySock;
  // memcpy(&mySock, EXPLICIT_PUBLIC_IN, sizeof(mySock));
  // static struct socket mySocket = {0};
  // mySocket.sk = &mySock;
  // static char optname; optname = *(EXPLICIT_PUBLIC_IN + sizeof(mySock));
  // static char optval[80];
  // static int optlen = sizeof(optval);

  static int pos = 0;

  static struct hci_conn myHciConn;
  myHciConn = *(struct hci_conn *)(EXPLICIT_PUBLIC_IN);
  pos += sizeof(myHciConn);

  static struct sco_conn myScoConn;
  myScoConn = *(struct sco_conn *)(EXPLICIT_PUBLIC_IN + pos);
  pos += sizeof(myScoConn);
  myScoConn.hcon = &myHciConn;

  static struct sco_pinfo myPinfo = {};
  myPinfo = *(struct sco_pinfo *)(EXPLICIT_PUBLIC_IN + pos);
  pos += sizeof(myPinfo);
  myPinfo.conn = &myScoConn;

  static struct sock *mySock = (struct sock *)&myPinfo;
  static struct socket mySocket = {0};
  mySocket.sk = mySock;

  static int optname; 
  optname = *(EXPLICIT_PUBLIC_IN + pos);
  static char optval[80];
  static int optlen = sizeof(optval);
  
  static int res;
  res = sco_sock_getsockopt_old(&mySocket, optname, optval, &optlen);
  write(1, &res, sizeof(res));
  write(1, optval, optlen);
}
