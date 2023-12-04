// Paired back implementation of CVE-2011-1078

#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t  __u8;


#define	EFAULT		14	/* Bad address */
#define	ENOPROTOOPT	42	/* Protocol not available */
#define	ENOTCONN	57	/* Transport endpoint is not connected */

struct socket {
//	socket_state		state;
//	short			type;
//	unsigned long		flags;
//	struct file		*file;
	struct sock		*sk;
//	const struct proto_ops	*ops; /* Might change with IPV6_ADDRFORM or MPTCP. */
//	struct socket_wq	wq;
};

struct sock_common {
	volatile unsigned char	skc_state;
};

struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_state		__sk_common.skc_state
	// ...
};

struct hci_conn {
	// ...
	__u16		handle;
	// ...
	__u8		dev_class[3];
	// ...
};


/* ---- SCO connections ---- */
struct sco_conn {
	struct hci_conn	*hcon;

//	spinlock_t	lock;
//	struct sock	*sk;

//	struct delayed_work	timeout_work;

	unsigned int    mtu;
};

/* ----- SCO socket info ----- */
#define sco_pi(sk) ((struct sco_pinfo *) sk)

struct sco_pinfo {
//	struct bt_sock	bt;
//	bdaddr_t	src;
//	bdaddr_t	dst;
	__u32		flags;
	__u16		setting;
//	struct bt_codec codec;
	struct sco_conn	*conn;
};

/* SCO socket options */
#define SCO_OPTIONS	0x01
struct sco_options {
	__u16 mtu;
};

#define SCO_CONNINFO	0x02
struct sco_conninfo {
	__u16 hci_handle;
	__u8  dev_class[3];
};

/* Connection and socket states */
enum {
	BT_CONNECTED = 1, /* Equal to TCP_ESTABLISHED to make net code happy */
	BT_OPEN,
	BT_BOUND,
	BT_LISTEN,
	BT_CONNECT,
	BT_CONNECT2,
	BT_CONFIG,
	BT_DISCONN,
	BT_CLOSED
};

/**
 * min_t - return minimum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define min_t(type, x, y)	(type)(x) < (type)(y) ? (type)(x) : (type)(y)

static inline void lock_sock(struct sock *sk)
{
	// lock_sock_nested(sk, 0);
}

void release_sock(struct sock *sk) {}

int copy_to_user(char *dest, char *src, int len) 
{
	memcpy(dest, src, len);
	return 0;
}

#define get_user(dest, src) dest = *src, 0

#define __user 
static int sco_sock_getsockopt_old(struct socket *sock, int optname, char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct sco_options opts;
	struct sco_conninfo cinfo;
	int len, err = 0;

	// BT_DBG("sk %p", sk);

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case SCO_OPTIONS:
		if (sk->sk_state != BT_CONNECTED) {
			err = -ENOTCONN;
			break;
		}

		opts.mtu = sco_pi(sk)->conn->mtu;

		// BT_DBG("mtu %d", opts.mtu);

		len = min_t(unsigned int, len, sizeof(opts));
		if (copy_to_user(optval, (char *)&opts, len))
			err = -EFAULT;

		break;

	case SCO_CONNINFO:
		if (sk->sk_state != BT_CONNECTED) {
			err = -ENOTCONN;
			break;
		}

		// memset(&cinfo, 0, sizeof(cinfo)); // FIX!
		cinfo.hci_handle = sco_pi(sk)->conn->hcon->handle;
		memcpy(cinfo.dev_class, sco_pi(sk)->conn->hcon->dev_class, 3);

		len = min_t(unsigned int, len, sizeof(cinfo));
		if (copy_to_user(optval, (char *)&cinfo, len))
			err = -EFAULT;

		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}
// 
// int main(void) 
// {
// 	struct sock mySock = {};
// 	struct socket mySocket = { .sk = &mySock };
// 	int optname = SCO_CONNINFO;
// 	char optval[80];
// 	int optlen = sizeof(optval);
// 
// 	int res = sco_sock_getsockopt_old(&mySocket, optname, optval, &optlen);
// 	printf("res: %d, optlen: %d, optval: [", res, optlen);
// 	for (int i = 0; i < optlen; i++) {
// 		printf("%02hhX", optval[i]);
// 	}
// 	printf("]\n");
// }
