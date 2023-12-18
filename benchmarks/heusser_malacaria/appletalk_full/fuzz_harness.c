/// Harness

#include "memory.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "atalk.c"

__AFL_FUZZ_INIT();

int peer;

int main(int argc, char **argv) 
{
	__AFL_INIT();

  // handle PUBLIC

	if (EXPLICIT_PUBLIC_LEN < sizeof(struct atalk_sock) + sizeof(int)) return 1;

	static struct socket sock = {0};
	static struct atalk_sock a_sock = {0};
	memcpy(&a_sock, EXPLICIT_PUBLIC_IN, sizeof(a_sock));
	sock.sk = (struct sock *)&a_sock;

	static struct sockaddr_at uaddr = {0};
	static int uaddr_len;
	peer = *(int *)(EXPLICIT_PUBLIC_IN + sizeof(a_sock));

  // handle SECRET
  initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);
  FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);

  // execute the function

	if (atalk_getname(&sock, (struct sockaddr *)&uaddr, &uaddr_len, peer) >= 0) {
    		write(1, &uaddr, sizeof(uaddr));
		putc('\n', stdout);
		fflush(stdout);
	}

    return 0;
}

// #include "base64.h"

// int main() {
// 	struct atalk_sock sock = {0};
// 	int peer = 0;

// 	char buf[sizeof(sock) + sizeof(peer)];
// 	memcpy(buf, &sock, sizeof(sock));
// 	memcpy(buf + sizeof(sock), &peer, sizeof(peer));

// 	int enc_len = Base64encode_len(sizeof(buf));
// 	char *encoded = malloc(enc_len);
// 	int res = Base64encode(encoded, buf, sizeof(buf));
// 	for (int i = 0; i < res; i++) {
// 		printf("%c", encoded[i]);
// 	}
// 	printf("\npredicted len: %d, actual: %d\n", enc_len, res);
// }
