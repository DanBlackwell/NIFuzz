#include <string.h>


/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/asm-generic/errno.h?id=f6b97b29513950bfbf621a83d85b6f86b39ec8db

#define	ENOBUFS		105	/* No buffer space available */
// ...
#define	ENOTCONN	107	/* Transport endpoint is not connected */


/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/socket.h?id=f6b97b29513950bfbf621a83d85b6f86b39ec8db

#define AF_APPLETALK	5	/* AppleTalk DDP 		*/


/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp_states.h?id=f6b97b29513950bfbf621a83d85b6f86b39ec8db

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */

	TCP_MAX_STATES	/* Leave at the end! */
};


/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/sock.h?id=f6b97b29513950bfbf621a83d85b6f86b39ec8db

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_nulls_node: main hash linkage for UDP/UDP-Lite protocol
 *	@skc_refcnt: reference count
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_prot: protocol handlers inside a network family
 *	@skc_net: reference to the network namespace of this socket
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
struct sock_common {
	/*
	 * first fields are not copied in sock_copy()
	 */
	// union {
	// 	struct hlist_node	skc_node;
	// 	struct hlist_nulls_node skc_nulls_node;
	// };
	// atomic_t		skc_refcnt;

	// unsigned int		skc_hash;
	// unsigned short		skc_family;
	volatile unsigned char	skc_state;
// 	unsigned char		skc_reuse;
// 	int			skc_bound_dev_if;
// 	struct hlist_node	skc_bind_node;
// 	struct proto		*skc_prot;
// #ifdef CONFIG_NET_NS
// 	struct net	 	*skc_net;
// #endif
};

/**
  *	struct sock - network layer representation of sockets
 */
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
// #define sk_node			__sk_common.skc_node
// #define sk_nulls_node		__sk_common.skc_nulls_node
// #define sk_refcnt		__sk_common.skc_refcnt

// #define sk_copy_start		__sk_common.skc_hash
// #define sk_hash			__sk_common.skc_hash
// #define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
// #define sk_reuse		__sk_common.skc_reuse
// #define sk_bound_dev_if		__sk_common.skc_bound_dev_if
// #define sk_bind_node		__sk_common.skc_bind_node
// #define sk_prot			__sk_common.skc_prot
// #define sk_net			__sk_common.skc_net
// 	kmemcheck_bitfield_begin(flags);
// 	unsigned char		sk_shutdown : 2,
// 				sk_no_check : 2,
// 				sk_userlocks : 4;
// 	kmemcheck_bitfield_end(flags);
// 	unsigned char		sk_protocol;
// 	unsigned short		sk_type;
// 	int			sk_rcvbuf;
// 	socket_lock_t		sk_lock;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 */
// 	struct {
// 		struct sk_buff *head;
// 		struct sk_buff *tail;
// 	} sk_backlog;
// 	wait_queue_head_t	*sk_sleep;
// 	struct dst_entry	*sk_dst_cache;
// #ifdef CONFIG_XFRM
// 	struct xfrm_policy	*sk_policy[2];
// #endif
// 	rwlock_t		sk_dst_lock;
// 	atomic_t		sk_rmem_alloc;
// 	atomic_t		sk_wmem_alloc;
// 	atomic_t		sk_omem_alloc;
// 	int			sk_sndbuf;
// 	struct sk_buff_head	sk_receive_queue;
// 	struct sk_buff_head	sk_write_queue;
// #ifdef CONFIG_NET_DMA
// 	struct sk_buff_head	sk_async_wait_queue;
// #endif
// 	int			sk_wmem_queued;
// 	int			sk_forward_alloc;
// 	gfp_t			sk_allocation;
// 	int			sk_route_caps;
// 	int			sk_gso_type;
// 	unsigned int		sk_gso_max_size;
// 	int			sk_rcvlowat;
	unsigned long 		sk_flags;
// 	unsigned long	        sk_lingertime;
// 	struct sk_buff_head	sk_error_queue;
// 	struct proto		*sk_prot_creator;
// 	rwlock_t		sk_callback_lock;
// 	int			sk_err,
// 				sk_err_soft;
// 	atomic_t		sk_drops;
// 	unsigned short		sk_ack_backlog;
// 	unsigned short		sk_max_ack_backlog;
// 	__u32			sk_priority;
// 	struct ucred		sk_peercred;
// 	long			sk_rcvtimeo;
// 	long			sk_sndtimeo;
// 	struct sk_filter      	*sk_filter;
// 	void			*sk_protinfo;
// 	struct timer_list	sk_timer;
// 	ktime_t			sk_stamp;
// 	struct socket		*sk_socket;
// 	void			*sk_user_data;
// 	struct page		*sk_sndmsg_page;
// 	struct sk_buff		*sk_send_head;
// 	__u32			sk_sndmsg_off;
// 	int			sk_write_pending;
// #ifdef CONFIG_SECURITY
// 	void			*sk_security;
// #endif
// 	__u32			sk_mark;
// 	/* XXX 4 bytes hole on 64 bit */
// 	void			(*sk_state_change)(struct sock *sk);
// 	void			(*sk_data_ready)(struct sock *sk, int bytes);
// 	void			(*sk_write_space)(struct sock *sk);
// 	void			(*sk_error_report)(struct sock *sk);
//   	int			(*sk_backlog_rcv)(struct sock *sk,
// 						  struct sk_buff *skb);  
// 	void                    (*sk_destruct)(struct sock *sk);
};

/* Sock flags */
enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
	SOCK_TIMESTAMPING_TX_HARDWARE,  /* %SOF_TIMESTAMPING_TX_HARDWARE */
	SOCK_TIMESTAMPING_TX_SOFTWARE,  /* %SOF_TIMESTAMPING_TX_SOFTWARE */
	SOCK_TIMESTAMPING_RX_HARDWARE,  /* %SOF_TIMESTAMPING_RX_HARDWARE */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_TIMESTAMPING_SOFTWARE,     /* %SOF_TIMESTAMPING_SOFTWARE */
	SOCK_TIMESTAMPING_RAW_HARDWARE, /* %SOF_TIMESTAMPING_RAW_HARDWARE */
	SOCK_TIMESTAMPING_SYS_HARDWARE, /* %SOF_TIMESTAMPING_SYS_HARDWARE */
};

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	// return test_bit(flag, &sk->sk_flags);
	return (sk->sk_flags >> flag) & 1;
}


/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/net.h?id=f6b97b29513950bfbf621a83d85b6f86b39ec8db

/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @type: socket type (%SOCK_STREAM, etc)
 *  @flags: socket flags (%SOCK_ASYNC_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @fasync_list: Asynchronous wake up list
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wait: wait queue for several uses
 */
struct socket {
	// socket_state		state;
	// short			type;
	// unsigned long		flags;
	/*
	 * Please keep fasync_list & wait fields in the same cache line
	 */
	// struct fasync_struct	*fasync_list;
	// wait_queue_head_t	wait;

	// struct file		*file;
	struct sock		*sk;
	// const struct proto_ops	*ops;
};


/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/atalk.h?id=3d392475c873c10c10d6d96b94d092a34ebd4791

// #ifndef __LINUX_ATALK_H__
// #define __LINUX_ATALK_H__

// #include <linux/types.h>
// #include <asm/byteorder.h>

/*
 * AppleTalk networking structures
 *
 * The following are directly referenced from the University Of Michigan
 * netatalk for compatibility reasons.
 */
// #define ATPORT_FIRST	1
// #define ATPORT_RESERVED	128
// #define ATPORT_LAST	254		/* 254 is only legal on localtalk */ 
// #define ATADDR_ANYNET	(__u16)0
// #define ATADDR_ANYNODE	(__u8)0
// #define ATADDR_ANYPORT  (__u8)0
// #define ATADDR_BCAST	(__u8)255
// #define DDP_MAXSZ	587
// #define DDP_MAXHOPS     15		/* 4 bits of hop counter */

// #define SIOCATALKDIFADDR       (SIOCPROTOPRIVATE + 0)

#define __u8 unsigned char
#define __be16 unsigned short

struct atalk_addr {
	__be16	s_net;
	__u8	s_node;
};

typedef unsigned short	sa_family_t;

struct sockaddr_at {
	sa_family_t	  sat_family;
	__u8		  sat_port;
	struct atalk_addr sat_addr;
	char		  sat_zero[8];
};

struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};

// struct atalk_netrange {
// 	__u8	nr_phase;
// 	__be16	nr_firstnet;
// 	__be16	nr_lastnet;
// };

// #ifdef __KERNEL__

// #include <net/sock.h>

// struct atalk_route {
// 	struct net_device  *dev;
// 	struct atalk_addr  target;
// 	struct atalk_addr  gateway;
// 	int		   flags;
// 	struct atalk_route *next;
// };

/**
 *	struct atalk_iface - AppleTalk Interface
 *	@dev - Network device associated with this interface
 *	@address - Our address
 *	@status - What are we doing?
 *	@nets - Associated direct netrange
 *	@next - next element in the list of interfaces
 */
// struct atalk_iface {
// 	struct net_device	*dev;
// 	struct atalk_addr	address;
// 	int			status;
// #define ATIF_PROBE	1		 // Probing for an address 
// #define ATIF_PROBE_FAIL	2		/* Probe collided */
// 	struct atalk_netrange	nets;
// 	struct atalk_iface	*next;
// };
	
struct atalk_sock {
	/* struct sock has to be the first member of atalk_sock */
	struct sock	sk;
	__be16		dest_net;
	__be16		src_net;
	unsigned char	dest_node;
	unsigned char	src_node;
	unsigned char	dest_port;
	unsigned char	src_port;
};

static inline struct atalk_sock *at_sk(struct sock *sk)
{
	return (struct atalk_sock *)sk;
}

// struct ddpehdr {
// 	__be16	deh_len_hops;	/* lower 10 bits are length, next 4 - hops */
// 	__be16	deh_sum;
// 	__be16	deh_dnet;
// 	__be16	deh_snet;
// 	__u8	deh_dnode;
// 	__u8	deh_snode;
// 	__u8	deh_dport;
// 	__u8	deh_sport;
// 	/* And netatalk apps expect to stick the type in themselves */
// };

// static __inline__ struct ddpehdr *ddp_hdr(struct sk_buff *skb)
// {
// 	return (struct ddpehdr *)skb_transport_header(skb);
// }

/* AppleTalk AARP headers */
// struct elapaarp {
// 	__be16	hw_type;
// #define AARP_HW_TYPE_ETHERNET		1
// #define AARP_HW_TYPE_TOKENRING		2
// 	__be16	pa_type;
// 	__u8	hw_len;
// 	__u8	pa_len;
// #define AARP_PA_ALEN			4
// 	__be16	function;
// #define AARP_REQUEST			1
// #define AARP_REPLY			2
// #define AARP_PROBE			3
// 	__u8	hw_src[ETH_ALEN];
// 	__u8	pa_src_zero;
// 	__be16	pa_src_net;
// 	__u8	pa_src_node;
// 	__u8	hw_dst[ETH_ALEN];
// 	__u8	pa_dst_zero;
// 	__be16	pa_dst_net;
// 	__u8	pa_dst_node;
// } __attribute__ ((packed));

// static __inline__ struct elapaarp *aarp_hdr(struct sk_buff *skb)
// {
// 	return (struct elapaarp *)skb_transport_header(skb);
// }

// /* Not specified - how long till we drop a resolved entry */
// #define AARP_EXPIRY_TIME	(5 * 60 * HZ)
// /* Size of hash table */
// #define AARP_HASH_SIZE		16
// /* Fast retransmission timer when resolving */
// #define AARP_TICK_TIME		(HZ / 5)
// /* Send 10 requests then give up (2 seconds) */
// #define AARP_RETRANSMIT_LIMIT	10

//  * Some value bigger than total retransmit time + a bit for last reply to
//  * appear and to stop continual requests
 
// #define AARP_RESOLVE_TIME	(10 * HZ)

// extern struct datalink_proto *ddp_dl, *aarp_dl;
// extern void aarp_proto_init(void);

// /* Inter module exports */

// /* Give a device find its atif control structure */
// static inline struct atalk_iface *atalk_find_dev(struct net_device *dev)
// {
// 	return dev->atalk_ptr;
// }

// extern struct atalk_addr *atalk_find_dev_addr(struct net_device *dev);
// extern struct net_device *atrtr_get_dev(struct atalk_addr *sa);
// extern int		 aarp_send_ddp(struct net_device *dev,
// 				       struct sk_buff *skb,
// 				       struct atalk_addr *sa, void *hwaddr);
// extern void		 aarp_device_down(struct net_device *dev);
// extern void		 aarp_probe_network(struct atalk_iface *atif);
// extern int 		 aarp_proxy_probe_network(struct atalk_iface *atif,
// 				     struct atalk_addr *sa);
// extern void		 aarp_proxy_remove(struct net_device *dev,
// 					   struct atalk_addr *sa);

// extern void		aarp_cleanup_module(void);

// extern struct hlist_head atalk_sockets;
// extern rwlock_t atalk_sockets_lock;

// extern struct atalk_route *atalk_routes;
// extern rwlock_t atalk_routes_lock;

// extern struct atalk_iface *atalk_interfaces;
// extern rwlock_t atalk_interfaces_lock;

// extern struct atalk_route atrtr_default;

// extern const struct file_operations atalk_seq_arp_fops;

// extern int sysctl_aarp_expiry_time;
// extern int sysctl_aarp_tick_time;
// extern int sysctl_aarp_retransmit_limit;
// extern int sysctl_aarp_resolve_time;

// #ifdef CONFIG_SYSCTL
// extern void atalk_register_sysctl(void);
// extern void atalk_unregister_sysctl(void);
// #else
// #define atalk_register_sysctl()		do { } while(0)
// #define atalk_unregister_sysctl()	do { } while(0)
// #endif

// #ifdef CONFIG_PROC_FS
// extern int atalk_proc_init(void);
// extern void atalk_proc_exit(void);
// #else
// #define atalk_proc_init()	({ 0; })
// #define atalk_proc_exit()	do { } while(0)
// #endif /* CONFIG_PROC_FS */

// #endif /* __KERNEL__ */
// #endif /* __LINUX_ATALK_H__ */

/// DIRECT FROM HEUSSER MALCARIA PAPER

// struct sockaddr_at {
// u_char sat_len, sat_family, sat_port;
// struct at_addr sat_addr;
// union {
// struct netrange r_netrange;
// char r_zero[ 8 ];
// } sat_range;
// };
// #define sat_zero sat_range.r_zero


/// ddp.c - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/appletalk/ddp.c?id=3d392475c873c10c10d6d96b94d092a34ebd4791

/**
 * atalk_pick_and_bind_port - Pick a source port when one is not given
 * @sk - socket to insert into the tables
 * @sat - address to search for
 *
 * Pick a source port when one is not given. If we can find a suitable free
 * one, we insert the socket into the tables using it.
 *
 * This whole operation must be atomic.
 */
static int atalk_pick_and_bind_port(struct sock *sk, struct sockaddr_at *sat)
{
	int retval;

	// write_lock_bh(&atalk_sockets_lock);

	// for (sat->sat_port = ATPORT_RESERVED;
	//      sat->sat_port < ATPORT_LAST;
	//      sat->sat_port++) {
	// 	struct sock *s;
	// 	struct hlist_node *node;

	// 	sk_for_each(s, node, &atalk_sockets) {
	// 		struct atalk_sock *at = at_sk(s);

	// 		if (at->src_net == sat->sat_addr.s_net &&
	// 		    at->src_node == sat->sat_addr.s_node &&
	// 		    at->src_port == sat->sat_port)
	// 			goto try_next_port;
	// 	}

	// 	/* Wheee, it's free, assign and insert. */
	// 	__atalk_insert_socket(sk);
	// 	at_sk(sk)->src_port = sat->sat_port;
		retval = 0;
		goto out;

// try_next_port:;
// 	}

// 	retval = -EBUSY;
out:
	// write_unlock_bh(&atalk_sockets_lock);
	return retval;
}


/*
 * Find the name of an AppleTalk socket. Just copy the right
 * fields into the sockaddr.
 */
__attribute_noinline__
static int atalk_getname(struct socket *sock, struct sockaddr *uaddr,
			 int *uaddr_len, int peer)
{
	struct sockaddr_at sat;
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);

	if (sock_flag(sk, SOCK_ZAPPED))
		// if (atalk_autobind(sk) < 0)
			return -ENOBUFS;

	*uaddr_len = sizeof(struct sockaddr_at);
//	memset(&sat.sat_zero, 0, sizeof(sat.sat_zero)); // FIX 1: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3d392475c873c10c10d6d96b94d092a34ebd4791
//  memset(&sat, 0, sizeof(sat)); // ACTUAL FIX (seen in later kernel versions, as FIX 1 misses padding)

	if (peer) {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -ENOTCONN;

		sat.sat_addr.s_net  = at->dest_net;
		sat.sat_addr.s_node = at->dest_node;
		sat.sat_port	    = at->dest_port;
	} else {
		sat.sat_addr.s_net  = at->src_net;
		sat.sat_addr.s_node = at->src_node;
		sat.sat_port	    = at->src_port;
	}

	sat.sat_family = AF_APPLETALK;
	memcpy(uaddr, &sat, sizeof(sat));
	return 0;
}

/// Harness

#include "memory.h"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

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
