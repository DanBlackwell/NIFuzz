#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "atalk.h"
#include "memory.h"

__AFL_FUZZ_INIT();

__attribute__((optnone))
int atalk_getname(atptr sock, atptr uaddr, int peer) {
/*
    atptr sock:  low input
    int peer: low input
    atptr uaddr: low output
    secret: is the machine information
*/
  struct atalk_sock sat;

	int err = -ENOBUF;
	if (sock_flag(sock))
		goto out;

	if (peer)
	{
		err = -ENOTCON;
		if (sock->sk_state != TCP_ESTABLISHED)
			goto out;
		sat.src_node  	= sock->dst_node;
		sat.src_port	= sock->dst_port;
		sat.dst_node 	= sock->src_node;
		sat.dst_port	= sock->src_port;
	} else {
		sat.src_node  	= sock->src_node;
		sat.src_port	= sock->src_port;
		sat.dst_node 	= sock->dst_node;
		sat.dst_port	= sock->dst_port;
	}

  sat.sk_state = sock->sk_state;
	memcpy(uaddr, &sat, sizeof(sat));
	err = sizeof(struct atalk_sock);

out:
	return err;
}

int main(int argc, char **argv) {

  __AFL_INIT();

  const unsigned char *Data = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
  const unsigned int Size = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

  // unsigned char Data[] = {28, 0, 0, 0, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0, 0, 1};
  // int Size = sizeof(Data);

  // char Data[1024 * 1024 * 2] = {0};

	// ssize_t Size;
	// Size = read(STDIN_FILENO, Data, 1024 * 1024 * 2);

  const uint32_t public_len = *(unsigned int *)Data;
  const uint32_t secret_len = Size - public_len - sizeof(public_len);
  const uint8_t *public_in = Data + sizeof(public_len);
  const uint8_t *secret_in = public_in + public_len;

  if (public_len != sizeof(struct atalk_sock) + sizeof(int)) {
    printf("Expected public len %lu\n", sizeof(struct atalk_sock) + 4);
    // printf("Expected public len %lu, was %u bytes [%hhu, %hhu, %hhu, %hhu]\n", sizeof(struct atalk_sock) + 4, public_len, Data[0], Data[1], Data[2], Data[3]);
    // printf("Data (len: NA): [", Size);
    // for (int i = 0; i < 4 + public_len; i++) 
    //   printf("%hhu, ", Data[i]);
    // printf("\b\b]\n");
    // // printf("__afl_fuzz_ptr: %p, public_in: %p, stack_bottom: %p\n", Data, &public_in, get_cur_stack_bottom());

    // abort();
    exit(1);
  }

  uint32_t seed = 0;
  for (int i = 0; i < (secret_len < 4 ? secret_len : 4); i++) {
      seed |= secret_in[i] << 8 * i;
  }

  struct atalk_sock sock = {0};
  memcpy(&sock, public_in, sizeof(sock));
  // atptr sock = (atptr)public_in;

  atptr uaddr = (atptr)calloc(1, sizeof(struct atalk_sock));
  if (!uaddr) return 1;
  int peer = *(int *)(public_in + sizeof(sock)) % 2;
  int res, i;

  SEED_MEMORY(seed);
  FILL_STACK();

  res = atalk_getname(&sock, uaddr, peer);

  printf("res: %d\n", res);
  for (i = 0; i < sizeof(* uaddr); i++) {
    printf("%02hhX", ((char *)uaddr)[i]);
  }
  printf("\n");
  free(uaddr);

  // RESTORE_STACK();

  return 0;
}
