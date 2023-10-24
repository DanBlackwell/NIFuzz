/// Harness

#include "memory.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "atalk.c"

__AFL_FUZZ_INIT();

int main(int argc, char **argv) 
{
	__AFL_INIT();
	
	unsigned char *Data = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
	int Size = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a

	// unsigned char *Data; int Size;
	uint32_t public_len = *(unsigned int *)Data;
	uint32_t secret_len = Size - public_len - sizeof(public_len);
	const uint8_t *public_in = Data + sizeof(public_len);
	const uint8_t *secret_in = public_in + public_len;

    // handle PUBLIC

	if (public_len < sizeof(struct atalk_sock) + sizeof(int)) return 1;

	struct socket sock = {0};
	struct atalk_sock a_sock = {0};
	memcpy(&a_sock, public_in, sizeof(a_sock));
	sock.sk = (struct sock *)&a_sock;

	struct sockaddr uaddr = {0};
	int uaddr_len;
	int peer = *(int *)(public_in + sizeof(a_sock));

    // handle SECRET

    uint32_t seed = 0;
	for (int i = 0; i < (secret_len < 4 ? secret_len : 4); i++) {
		seed |= secret_in[i] << 8 * i;
	}

	SEED_MEMORY(seed);
	FILL_STACK();

	// printf("stack: ");
	// for (int i = 0; i < 300; i++) printf("%hhX", *(((char *)&seed) - i));
	// printf(". ");

    // execute the function

	if (atalk_getname(&sock, &uaddr, &uaddr_len, peer) >= 0) {
		printf("%hu", uaddr.sa_family);
		for (int i = 0; i < sizeof(uaddr.sa_data); i++) {
			printf("%hhX", uaddr.sa_data[i]);
		}
		printf("\n");
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
