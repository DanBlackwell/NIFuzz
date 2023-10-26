/// Harness

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "distinctions.h"

#include "atalk.c"

#define INIT_INPUT(num) 
#define GENERATE_OUTPUT(num) struct sockaddr output ## num = {0}; atalk_getname(&sock, &output ## num, &uaddr_len, peer);
#define OUTPUTS_EQUAL(out1, out2) (output ## out1.sa_family == output ## out2.sa_family && !memcmp(output ## out1.sa_data, output ## out2.sa_data, sizeof(output ## out1.sa_data)))

int main(void) 
{
	struct socket sock = {0};
	struct atalk_sock a_sock;
	sock.sk = (struct sock *)&a_sock;

	int uaddr_len;
	int peer;

	CHECK_LEAKAGE()

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
