/// Harness

#include "memory.h"
#include "generate_random.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "atalk.c"

int main(int argc, char **argv) 
{
  time_t t;
  srand(time(&t));

	for (int i = 0; i < SAMPLES / REPS; i++) {
		// handle PUBLIC

		struct socket sock = {0};
		struct atalk_sock a_sock = {0};

		FILL_RAND_VAR(a_sock);
		sock.sk = (struct sock *)&a_sock;

		struct sockaddr uaddr = {0};
		int uaddr_len;
		int peer;
		FILL_RAND_VAR(peer);

		// handle SECRET
		
		uint32_t mem_seed;
		FILL_RAND_VAR(mem_seed);

		// printf("stack: ");
		// for (int i = 0; i < 300; i++) printf("%hhX", *(((char *)&seed) - i));
		// printf(". ");

		// execute the function

    for (int reps = 0; reps < REPS; reps++) {
		  SEED_MEMORY(mem_seed);
		  FILL_STACK();

		  int res = atalk_getname(&sock, &uaddr, &uaddr_len, peer);
		  printf("(%u,%d", mem_seed, res);
		  if (res >= 0) {
		  	printf(" %hu", uaddr.sa_family);
		  	for (int i = 0; i < sizeof(uaddr.sa_data); i++) {
		  		printf("%02hhX", uaddr.sa_data[i]);
		  	}
		  }
		  printf(")\n");
    }
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
