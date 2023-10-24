#include <string.h>
#include <stdlib.h>

#define unlikely(x) x
typedef unsigned int sk_buff_data_t;

struct sk_buff {
//        /* These two members must be first. */
//        struct sk_buff          *next;
//        struct sk_buff          *prev;
//
//        struct sock             *sk;
//        ktime_t                 tstamp;
//        struct net_device       *dev;
//
//        unsigned long           _skb_dst;
//#ifdef CONFIG_XFRM
//        struct  sec_path        *sp;
//#endif
//        /*
//         * This is the control buffer. It is free to use for every
//         * layer. Please put your private variables there. If you
//         * want to keep them across layers you have to do a skb_clone()
//         * first. This is owned by whoever has the skb queued ATM.
//         */
//        char                    cb[48];
//
        unsigned int            len,
                                data_len;
//        __u16                   mac_len,
//                                hdr_len;
//        union {
//                __wsum          csum;
//                struct {
//                        __u16   csum_start;
//                        __u16   csum_offset;
//                };
//        };
//        __u32                   priority;
//        kmemcheck_bitfield_begin(flags1);
//        __u8                    local_df:1,
//                                cloned:1,
//                                ip_summed:2,
//                                nohdr:1,
//                                nfctinfo:3;
//        __u8                    pkt_type:3,
//                                fclone:2,
//                                ipvs_property:1,
//                                peeked:1,
//                                nf_trace:1;
//        __be16                  protocol:16;
//        kmemcheck_bitfield_end(flags1);
//
//        void                    (*destructor)(struct sk_buff *skb);
//#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
//        struct nf_conntrack     *nfct;
//        struct sk_buff          *nfct_reasm;
//#endif
//#ifdef CONFIG_BRIDGE_NETFILTER
//        struct nf_bridge_info   *nf_bridge;
//#endif
//
//        int                     iif;
//#ifdef CONFIG_NET_SCHED
//        __u16                   tc_index;       /* traffic control index */
//#ifdef CONFIG_NET_CLS_ACT
//        __u16                   tc_verd;        /* traffic control verdict */
//#endif
//#endif
//
//        kmemcheck_bitfield_begin(flags2);
//        __u16                   queue_mapping:16;
//#ifdef CONFIG_IPV6_NDISC_NODETYPE
//        __u8                    ndisc_nodetype:2;
//#endif
//        kmemcheck_bitfield_end(flags2);
//
//        /* 0/14 bit hole */
//
//#ifdef CONFIG_NET_DMA
//        dma_cookie_t            dma_cookie;
//#endif
//#ifdef CONFIG_NETWORK_SECMARK
//        __u32                   secmark;
//#endif
//
//        __u32                   mark;
//
//        __u16                   vlan_tci;
//
//        sk_buff_data_t          transport_header;
//        sk_buff_data_t          network_header;
//        sk_buff_data_t          mac_header;
//        /* These elements must be at the end, see alloc_skb() for details.  */
        sk_buff_data_t          tail;
        sk_buff_data_t          end;
        unsigned char           *head,
                                *data;
//        unsigned int            truesize;
//        atomic_t                users;
};

typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long __u64;
typedef unsigned short __be16;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct nlmsghdr
{
        __u32           nlmsg_len;      /* Length of message including header */
        __u16           nlmsg_type;     /* Message content */
        __u16           nlmsg_flags;    /* Additional flags */
        __u32           nlmsg_seq;      /* Sequence number */
        __u32           nlmsg_pid;      /* Sending process port ID */
};

#define NLMSG_NEW(skb, pid, seq, type, len, flags) \
({      if (unlikely(skb_tailroom(skb) < (int)NLMSG_SPACE(len))) \
                goto nlmsg_failure; \
        __nlmsg_put(skb, pid, seq, type, len, flags); })

#define NLMSG_ALIGNTO   4
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN     ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

unsigned char *skb_put(struct sk_buff *skb, unsigned int len);

static struct nlmsghdr *
__nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int len, int flags)
{
        struct nlmsghdr *nlh;
        int size = NLMSG_LENGTH(len);

        nlh = (struct nlmsghdr*)skb_put(skb, NLMSG_ALIGN(size));
        nlh->nlmsg_type = type;
        nlh->nlmsg_len = size;
        nlh->nlmsg_flags = flags;
        nlh->nlmsg_pid = pid;
        nlh->nlmsg_seq = seq;
        if (!__builtin_constant_p(size) || NLMSG_ALIGN(size) - size != 0)
                memset(NLMSG_DATA(nlh) + len, 0, NLMSG_ALIGN(size) - size);
        return nlh;
}

struct net_device
{
//
//        /*
//         * This is the first field of the "visible" part of this structure
//         * (i.e. as seen by users in the "Space.c" file).  It is the name
//         * the interface.
//         */
//        char                    name[IFNAMSIZ];
//        /* device name hash chain */
//        struct hlist_node       name_hlist;
//        /* snmp alias */
//        char                    *ifalias;
//
//        /*
//         *      I/O specific fields
//         *      FIXME: Merge these and struct ifmap into one
//         */
//        unsigned long           mem_end;        /* shared mem end       */
//        unsigned long           mem_start;      /* shared mem start     */
//        unsigned long           base_addr;      /* device I/O address   */
//        unsigned int            irq;            /* device IRQ number    */
//
//        /*
//         *      Some hardware also needs these fields, but they are not
//         *      part of the usual set specified in Space.c.
//         */
//
//        unsigned char           if_port;        /* Selectable AUI, TP,..*/
//        unsigned char           dma;            /* DMA channel          */
//
//        unsigned long           state;
//
//        struct list_head        dev_list;
//        struct list_head        napi_list;
//
//        /* Net device features */
//        unsigned long           features;
//#define NETIF_F_SG              1       /* Scatter/gather IO. */
//#define NETIF_F_IP_CSUM         2       /* Can checksum TCP/UDP over IPv4. */
//#define NETIF_F_NO_CSUM         4       /* Does not require checksum. F.e. loopack. */
//#define NETIF_F_HW_CSUM         8       /* Can checksum all the packets. */
//#define NETIF_F_IPV6_CSUM       16      /* Can checksum TCP/UDP over IPV6 */
//#define NETIF_F_HIGHDMA         32      /* Can DMA to high memory. */
//#define NETIF_F_FRAGLIST        64      /* Scatter/gather IO. */
//#define NETIF_F_HW_VLAN_TX      128     /* Transmit VLAN hw acceleration */
//#define NETIF_F_HW_VLAN_RX      256     /* Receive VLAN hw acceleration */
//#define NETIF_F_HW_VLAN_FILTER  512     /* Receive filtering on VLAN */
//#define NETIF_F_VLAN_CHALLENGED 1024    /* Device cannot handle VLAN packets */
//#define NETIF_F_GSO             2048    /* Enable software GSO. */
//#define NETIF_F_LLTX            4096    /* LockLess TX - deprecated. Please */
//                                        /* do not use LLTX in new drivers */
//#define NETIF_F_NETNS_LOCAL     8192    /* Does not change network namespaces */
//#define NETIF_F_GRO             16384   /* Generic receive offload */
//#define NETIF_F_LRO             32768   /* large receive offload */
//
///* the GSO_MASK reserves bits 16 through 23 */
//#define NETIF_F_FCOE_CRC        (1 << 24) /* FCoE CRC32 */
//#define NETIF_F_SCTP_CSUM       (1 << 25) /* SCTP checksum offload */
//#define NETIF_F_FCOE_MTU        (1 << 26) /* Supports max FCoE MTU, 2158 bytes*/
//
//        /* Segmentation offload features */
//#define NETIF_F_GSO_SHIFT       16
//#define NETIF_F_GSO_MASK        0x00ff0000
//#define NETIF_F_TSO             (SKB_GSO_TCPV4 << NETIF_F_GSO_SHIFT)
//#define NETIF_F_UFO             (SKB_GSO_UDP << NETIF_F_GSO_SHIFT)
//#define NETIF_F_GSO_ROBUST      (SKB_GSO_DODGY << NETIF_F_GSO_SHIFT)
//#define NETIF_F_TSO_ECN         (SKB_GSO_TCP_ECN << NETIF_F_GSO_SHIFT)
//#define NETIF_F_TSO6            (SKB_GSO_TCPV6 << NETIF_F_GSO_SHIFT)
//#define NETIF_F_FSO             (SKB_GSO_FCOE << NETIF_F_GSO_SHIFT)
//
//        /* List of features with software fallbacks. */
//#define NETIF_F_GSO_SOFTWARE    (NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6)
//
//
//#define NETIF_F_GEN_CSUM        (NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
//#define NETIF_F_V4_CSUM         (NETIF_F_GEN_CSUM | NETIF_F_IP_CSUM)
//#define NETIF_F_V6_CSUM         (NETIF_F_GEN_CSUM | NETIF_F_IPV6_CSUM)
//#define NETIF_F_ALL_CSUM        (NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)
//
//        /*
//         * If one device supports one of these features, then enable them
//         * for all in netdev_increment_features.
//         */
//#define NETIF_F_ONE_FOR_ALL     (NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ROBUST | \
//                                 NETIF_F_SG | NETIF_F_HIGHDMA |         \
//                                 NETIF_F_FRAGLIST)
//
//        /* Interface index. Unique device identifier    */
        int                     ifindex;
//        int                     iflink;
//
//        struct net_device_stats stats;
//
//#ifdef CONFIG_WIRELESS_EXT
//        /* List of functions to handle Wireless Extensions (instead of ioctl).
//         * See <net/iw_handler.h> for details. Jean II */
//        const struct iw_handler_def *   wireless_handlers;
//        /* Instance data managed by the core of Wireless Extensions. */
//        struct iw_public_data * wireless_data;
//#endif
//        /* Management operations */
//        const struct net_device_ops *netdev_ops;
//        const struct ethtool_ops *ethtool_ops;
//
//        /* Hardware header description */
//        const struct header_ops *header_ops;
//
//        unsigned int            flags;  /* interface flags (a la BSD)   */
//        unsigned short          gflags;
//        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
//        unsigned short          padded; /* How much padding added by alloc_netdev() */
//
//        unsigned char           operstate; /* RFC2863 operstate */
//        unsigned char           link_mode; /* mapping policy to operstate */
//
//        unsigned                mtu;    /* interface MTU value          */
//        unsigned short          type;   /* interface hardware type      */
//        unsigned short          hard_header_len;        /* hardware hdr length  */
//
//        /* extra head- and tailroom the hardware may need, but not in all cases
//         * can this be guaranteed, especially tailroom. Some cases also use
//         * LL_MAX_HEADER instead to allocate the skb.
//         */
//        unsigned short          needed_headroom;
//        unsigned short          needed_tailroom;
//
//        struct net_device       *master; /* Pointer to master device of a group,
//                                          * which this device is member of.
//                                          */
//
//        /* Interface address info. */
//        unsigned char           perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
//        unsigned char           addr_len;       /* hardware address length      */
//        unsigned short          dev_id;         /* for shared network cards */
//
//        struct netdev_hw_addr_list      uc;     /* Secondary unicast
//                                                   mac addresses */
//        int                     uc_promisc;
//        spinlock_t              addr_list_lock;
//        struct dev_addr_list    *mc_list;       /* Multicast mac addresses      */
//        int                     mc_count;       /* Number of installed mcasts   */
//        unsigned int            promiscuity;
//        unsigned int            allmulti;
//
//
//        /* Protocol specific pointers */
//
//#ifdef CONFIG_NET_DSA
//        void                    *dsa_ptr;       /* dsa specific data */
//#endif
//        void                    *atalk_ptr;     /* AppleTalk link       */
//        void                    *ip_ptr;        /* IPv4 specific data   */
//        void                    *dn_ptr;        /* DECnet specific data */
//        void                    *ip6_ptr;       /* IPv6 specific data */
//        void                    *ec_ptr;        /* Econet specific data */
//        void                    *ax25_ptr;      /* AX.25 specific data */
//        struct wireless_dev     *ieee80211_ptr; /* IEEE 802.11 specific data,
//                                                   assign before registering */
//
///*
// * Cache line mostly used on receive path (including eth_type_trans())
// */
//        unsigned long           last_rx;        /* Time of last Rx      */
//        /* Interface address info used in eth_type_trans() */
//        unsigned char           *dev_addr;      /* hw address, (before bcast
//                                                   because most packets are
//                                                   unicast) */
//
//        struct netdev_hw_addr_list      dev_addrs; /* list of device
//                                                      hw addresses */
//
//        unsigned char           broadcast[MAX_ADDR_LEN];        /* hw bcast add */
//
//        struct netdev_queue     rx_queue;
//
//        struct netdev_queue     *_tx ____cacheline_aligned_in_smp;
//
//        /* Number of TX queues allocated at alloc_netdev_mq() time  */
//        unsigned int            num_tx_queues;
//
//        /* Number of TX queues currently active in device  */
//        unsigned int            real_num_tx_queues;
//
//        /* root qdisc from userspace point of view */
//        struct Qdisc            *qdisc;
//
//        unsigned long           tx_queue_len;   /* Max frames per queue allowed */
//        spinlock_t              tx_global_lock;
///*
// * One part is mostly used on xmit path (device)
// */
//        /* These may be needed for future network-power-down code. */
//
//        /*
//         * trans_start here is expensive for high speed devices on SMP,
//         * please use netdev_queue->trans_start instead.
//         */
//        unsigned long           trans_start;    /* Time (in jiffies) of last Tx */
//
//        int                     watchdog_timeo; /* used by dev_watchdog() */
//        struct timer_list       watchdog_timer;
//
//        /* Number of references to this device */
//        atomic_t                refcnt ____cacheline_aligned_in_smp;
//
//        /* delayed register/unregister */
//        struct list_head        todo_list;
//        /* device index hash chain */
//        struct hlist_node       index_hlist;
//
//        struct net_device       *link_watch_next;
//
//        /* register/unregister state machine */
//        enum { NETREG_UNINITIALIZED=0,
//               NETREG_REGISTERED,       /* completed register_netdevice */
//               NETREG_UNREGISTERING,    /* called unregister_netdevice */
//               NETREG_UNREGISTERED,     /* completed unregister todo */
//               NETREG_RELEASED,         /* called free_netdev */
//               NETREG_DUMMY,            /* dummy device for NAPI poll */
//        } reg_state;
//
//        /* Called from unregister, can be used to call free_netdev */
//        void (*destructor)(struct net_device *dev);
//
//#ifdef CONFIG_NETPOLL
//        struct netpoll_info     *npinfo;
//#endif
//
//#ifdef CONFIG_NET_NS
//        /* Network namespace this network device is inside */
//        struct net              *nd_net;
//#endif
//
//        /* mid-layer private */
//        void                    *ml_priv;
//
//        /* bridge stuff */
//        struct net_bridge_port  *br_port;
//        /* macvlan */
//        struct macvlan_port     *macvlan_port;
//        /* GARP */
//        struct garp_port        *garp_port;
//
//        /* class/net/name entry */
//        struct device           dev;
//        /* space for optional statistics and wireless sysfs groups */
//        const struct attribute_group *sysfs_groups[3];
//
//        /* rtnetlink link ops */
//        const struct rtnl_link_ops *rtnl_link_ops;
//
//        /* VLAN feature mask */
//        unsigned long vlan_features;
//
//        /* for setting kernel sock attribute on TCP connection setup */
//#define GSO_MAX_SIZE            65536
//        unsigned int            gso_max_size;
//
//#ifdef CONFIG_DCB
//        /* Data Center Bridging netlink ops */
//        struct dcbnl_rtnl_ops *dcbnl_ops;
//#endif
//
//#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
//        /* max exchange id for FCoE LRO by ddp */
//        unsigned int            fcoe_ddp_xid;
//#endif
};

struct netdev_queue {
/*
 * read mostly part
 */
        struct net_device       *dev;
//        struct Qdisc            *qdisc;
//        unsigned long           state;
//        struct Qdisc            *qdisc_sleeping;
///*
// * write mostly part
// */
//        spinlock_t              _xmit_lock ____cacheline_aligned_in_smp;
//        int                     xmit_lock_owner;
//        /*
//         * please use this field instead of dev->trans_start
//         */
//        unsigned long           trans_start;
//        unsigned long           tx_bytes;
//        unsigned long           tx_packets;
//        unsigned long           tx_dropped;
};

struct Qdisc
{
//        int                     (*enqueue)(struct sk_buff *skb, struct Qdisc *dev);
//        struct sk_buff *        (*dequeue)(struct Qdisc *dev);
//        unsigned                flags;
//#define TCQ_F_BUILTIN           1
//#define TCQ_F_THROTTLED         2
//#define TCQ_F_INGRESS           4
//#define TCQ_F_CAN_BYPASS        8
//#define TCQ_F_MQROOT            16
//#define TCQ_F_WARN_NONWC        (1 << 16)
//        int                     padded;
//        struct Qdisc_ops        *ops;
//        struct qdisc_size_table *stab;
//        struct list_head        list;
//        u32                     handle;
//        u32                     parent;
//        atomic_t                refcnt;
//        struct gnet_stats_rate_est      rate_est;
//        int                     (*reshape_fail)(struct sk_buff *skb,
//                                        struct Qdisc *q);
//
//        void                    *u32_node;
//
//        /* This field is deprecated, but it is still used by CBQ
//         * and it will live until better solution will be invented.
//         */
//        struct Qdisc            *__parent;
        struct netdev_queue     *dev_queue;
//        struct Qdisc            *next_sched;
//
//        struct sk_buff          *gso_skb;
//        /*
//         * For performance sake on SMP, we put highly modified fields at the end
//         */
//        unsigned long           state;
//        struct sk_buff_head     q;
//        struct gnet_stats_basic_packed bstats;
//        struct gnet_stats_queue qstats;
};

struct tcf_proto;
struct tcmsg
{
        unsigned char   tcm_family;
        unsigned char   tcm__pad1;
        unsigned short  tcm__pad2;
        int             tcm_ifindex;
        __u32           tcm_handle;
        __u32           tcm_parent;
        __u32           tcm_info;
};


#define IFNAMSIZ        16
struct tcf_proto_ops
{
//        struct tcf_proto_ops    *next;
        char                    kind[IFNAMSIZ];
//
//        int                     (*classify)(struct sk_buff*, struct tcf_proto*,
//                                        struct tcf_result *);
//        int                     (*init)(struct tcf_proto*);
//        void                    (*destroy)(struct tcf_proto*);
//
//        unsigned long           (*get)(struct tcf_proto*, u32 handle);
//        void                    (*put)(struct tcf_proto*, unsigned long);
//        int                     (*change)(struct tcf_proto*, unsigned long,
//                                        u32 handle, struct nlattr **,
//                                        unsigned long *);
//        int                     (*delete)(struct tcf_proto*, unsigned long);
//        void                    (*walk)(struct tcf_proto*, struct tcf_walker *arg);
//
        /* rtnetlink specific */
        int                     (*dump)(struct tcf_proto*, unsigned long,
                                        struct sk_buff *skb, struct tcmsg*);

//        struct module           *owner;
};

struct tcf_proto
{
        /* Fast access part */
//        struct tcf_proto        *next;
//        void                    *root;
//        int                     (*classify)(struct sk_buff*, struct tcf_proto*,
//                                        struct tcf_result *);
        __be16                  protocol;
//
//        /* All the rest */
        u32                     prio;
        u32                     classid;
        struct Qdisc            *q;
//        void                    *data;
        struct tcf_proto_ops    *ops;
};

static inline struct net_device *qdisc_dev(struct Qdisc *qdisc)
{
        return qdisc->dev_queue->dev;
}


////////////////////////////////////////////////////////////////////////////////

static inline int skb_is_nonlinear(const struct sk_buff *skb)
{
        return skb->data_len;
}

static inline int skb_tailroom(const struct sk_buff *skb)
{
        return skb_is_nonlinear(skb) ? 0 : skb->end - skb->tail;
}

static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
        return skb->head + skb->tail;
}

static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
        skb->tail = skb->data - skb->head;
}

static inline void skb_set_tail_pointer(struct sk_buff *skb, const int offset)
{
        skb_reset_tail_pointer(skb);
        skb->tail += offset;
}

static inline void __skb_trim(struct sk_buff *skb, unsigned int len)
{
        if (unlikely(skb->data_len)) {
                return;
        }
        skb->len = len;
        skb_set_tail_pointer(skb, len);
}

void skb_trim(struct sk_buff *skb, unsigned int len)
{
        if (skb->len > len)
                __skb_trim(skb, len);
}

unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
        unsigned char *tmp = skb_tail_pointer(skb);
//        SKB_LINEAR_ASSERT(skb);
        skb->tail += len;
        skb->len  += len;
        if (unlikely(skb->tail > skb->end))
		abort();
//                skb_over_panic(skb, len, __builtin_return_address(0));
        return tmp;
}

///////////////////////////////////////////////////////////////////////////////

struct nlattr
{
        __u16           nla_len;
        __u16           nla_type;
};

#define NLA_ALIGNTO             4
#define NLA_ALIGN(len)          (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN              ((int) NLA_ALIGN(sizeof(struct nlattr)))

static inline void *nla_data(const struct nlattr *nla)
{
        return (char *) nla + NLA_HDRLEN;
}

static inline int nla_attr_size(int payload)
{
        return NLA_HDRLEN + payload;
}

static inline int nla_total_size(int payload)
{
        return NLA_ALIGN(nla_attr_size(payload));
}

static inline int nla_padlen(int payload)
{
        return nla_total_size(payload) - nla_attr_size(payload);
}

struct nlattr *__nla_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
        struct nlattr *nla;

        nla = (struct nlattr *) skb_put(skb, nla_total_size(attrlen));
        nla->nla_type = attrtype;
        nla->nla_len = nla_attr_size(attrlen);

        memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));

        return nla;
}

void __nla_put(struct sk_buff *skb, int attrtype, int attrlen,
                             const void *data)
{
        struct nlattr *nla;

        nla = __nla_reserve(skb, attrtype, attrlen);
        memcpy(nla_data(nla), data, attrlen);
}

#define EMSGSIZE        90      /* Message too long */
#define EINVAL          22      /* Invalid argument */

void *__nla_reserve_nohdr(struct sk_buff *skb, int attrlen)
{
        void *start;

        start = skb_put(skb, NLA_ALIGN(attrlen));
        memset(start, 0, NLA_ALIGN(attrlen));

        return start;
}

void __nla_put_nohdr(struct sk_buff *skb, int attrlen, const void *data)
{
        void *start;

        start = __nla_reserve_nohdr(skb, attrlen);
        memcpy(start, data, attrlen);
}

int nla_put_nohdr(struct sk_buff *skb, int attrlen, const void *data)
{
        if (unlikely(skb_tailroom(skb) < NLA_ALIGN(attrlen)))
                return -EMSGSIZE;

        __nla_put_nohdr(skb, attrlen, data);
        return 0;
}

int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)
{
        if (unlikely(skb_tailroom(skb) < nla_total_size(attrlen)))
                return -EMSGSIZE;

        __nla_put(skb, attrtype, attrlen, data);
        return 0;
}

#define AF_UNSPEC       0

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))

#define NLA_PUT(skb, attrtype, attrlen, data) \
        do { \
                if (unlikely(nla_put(skb, attrtype, attrlen, data) < 0)) \
                        goto nla_put_failure; \
        } while(0)
#define NLA_PUT_TYPE(skb, type, attrtype, value) \
        do { \
                type __tmp = value; \
                NLA_PUT(skb, attrtype, sizeof(type), &__tmp); \
        } while(0)
#define NLA_PUT_U32(skb, attrtype, value) \
        NLA_PUT_TYPE(skb, u32, attrtype, value)
#define NLA_PUT_STRING(skb, attrtype, value) \
        NLA_PUT(skb, attrtype, strlen(value) + 1, value)

#define RTM_DELTFILTER  44

enum
{
        TCA_UNSPEC,
        TCA_KIND,
        TCA_OPTIONS,
        TCA_STATS,
        TCA_XSTATS,
        TCA_RATE,
        TCA_FCNT,
        TCA_STATS2,
        TCA_STAB,
        __TCA_MAX
};

///////////////////////////////////////////////////////////////////////////////

static inline void nlmsg_trim(struct sk_buff *skb, const void *mark)
{
        if (mark)
                skb_trim(skb, (unsigned char *) mark - skb->data);
}

static inline struct nlattr *nla_nest_start(struct sk_buff *skb, int attrtype)
{
        struct nlattr *start = (struct nlattr *)skb_tail_pointer(skb);

        if (nla_put(skb, attrtype, 0, NULL) < 0)
                return NULL;

        return start;
}

static inline int nla_nest_end(struct sk_buff *skb, struct nlattr *start)
{
        start->nla_len = skb_tail_pointer(skb) - (unsigned char *)start;
        return skb->len;
}

static inline void nla_nest_cancel(struct sk_buff *skb, struct nlattr *start)
{
        nlmsg_trim(skb, start);
}

///////////////////////////////////////////////////////////////////////////////

struct tcf_result
{
        unsigned long   class;
        u32             classid;
};

struct tc_action;

struct tc_action_ops {
//        struct tc_action_ops *next;
//        struct tcf_hashinfo *hinfo;
        char    kind[IFNAMSIZ];
//        __u32   type; /* TBD to match kind */
//        __u32   capab;  /* capabilities includes 4 bit version */
//        struct module           *owner;
//        int     (*act)(struct sk_buff *, struct tc_action *, struct tcf_result *);
        int     (*get_stats)(struct sk_buff *, struct tc_action *);
        int     (*dump)(struct sk_buff *, struct tc_action *, int, int);
//        int     (*cleanup)(struct tc_action *, int bind);
//        int     (*lookup)(struct tc_action *, u32);
//        int     (*init)(struct nlattr *, struct nlattr *, struct tc_action *, int , int);
//        int     (*walk)(struct sk_buff *, struct netlink_callback *, int, struct tc_action *);
};

struct tc_action {
        void                    *priv;
        struct tc_action_ops    *ops;
        __u32                   type; /* for backward compat(TCA_OLD_COMPAT) */
        __u32                   order;
        struct tc_action        *next;
};

struct tcf_exts
{
#ifdef CONFIG_NET_CLS_ACT
        struct tc_action *action;
#endif
};

struct tcf_ematch_tree_hdr
{
        __u16           nmatches;
        __u16           progid;
};

struct tcf_ematch;

struct tcf_ematch_ops
{
        int                     kind;
//        int                     datalen;
//        int                     (*change)(struct tcf_proto *, void *,
//                                          int, struct tcf_ematch *);
//        int                     (*match)(struct sk_buff *, struct tcf_ematch *,
//                                         struct tcf_pkt_info *);
//        void                    (*destroy)(struct tcf_proto *,
//                                           struct tcf_ematch *);
        int                     (*dump)(struct sk_buff *, struct tcf_ematch *);
//        struct module           *owner;
//        struct list_head        link;
};

struct tcf_ematch
{
        struct tcf_ematch_ops * ops;
        unsigned long           data;
        unsigned int            datalen;
        u16                     matchid;
        u16                     flags;
};

static inline int tcf_em_is_container(struct tcf_ematch *em)
{
        return !em->ops;
}

#define TCF_EM_SIMPLE   (1<<3)

static inline int tcf_em_is_simple(struct tcf_ematch *em)
{
        return em->flags & TCF_EM_SIMPLE;
}

struct tcf_ematch_tree
{
        struct tcf_ematch_tree_hdr hdr;
        struct tcf_ematch *     matches;
        
};

struct tcf_ematch_hdr
{
        __u16           matchid;
        __u16           kind;
        __u16           flags;
        __u16           pad; /* currently unused */
};

#define TCF_EM_CONTAINER        0

struct list_head {
        struct list_head *next, *prev;
};

struct basic_filter
{
        u32                     handle;
        struct tcf_exts         exts;
        struct tcf_ematch_tree  ematches;
        struct tcf_result       res;
        struct list_head        link;
};

typedef int spinlock_t;

enum {
        TCA_STATS_UNSPEC,
        TCA_STATS_BASIC,
        TCA_STATS_RATE_EST,
        TCA_STATS_QUEUE,
        TCA_STATS_APP,
        __TCA_STATS_MAX,
};

struct tc_stats
{
        __u64   bytes;                  /* NUmber of enqueues bytes */
        __u32   packets;                /* Number of enqueued packets   */
        __u32   drops;                  /* Packets dropped because of lack of resources */
        __u32   overlimits;             /* Number of throttle events when this
                                         * flow goes out of allocated bandwidth */
        __u32   bps;                    /* Current flow byte rate */
        __u32   pps;                    /* Current flow packet rate */
        __u32   qlen;
        __u32   backlog;
};

struct gnet_dump
{
        spinlock_t *      lock;
        struct sk_buff *  skb;
        struct nlattr *   tail;

        /* Backward compatability */
        int               compat_tc_stats;
        int               compat_xstats;
        void *            xstats;
        int               xstats_len;
        struct tc_stats   tc_stats;
};

static inline int
gnet_stats_copy(struct gnet_dump *d, int type, void *buf, int size)
{
        NLA_PUT(d->skb, type, size, buf);
        return 0;

nla_put_failure:
//        spin_unlock_bh(d->lock);
        return -1;
}

int
gnet_stats_start_copy_compat(struct sk_buff *skb, int type, int tc_stats_type,
        int xstats_type, spinlock_t *lock, struct gnet_dump *d)
{
        memset(d, 0, sizeof(*d));

//        spin_lock_bh(lock);
        d->lock = lock;
        if (type)
                d->tail = (struct nlattr *)skb_tail_pointer(skb);
        d->skb = skb;
        d->compat_tc_stats = tc_stats_type;
        d->compat_xstats = xstats_type;

        if (d->tail)
                return gnet_stats_copy(d, type, NULL, 0);

        return 0;
}

int
gnet_stats_start_copy(struct sk_buff *skb, int type, spinlock_t *lock,
        struct gnet_dump *d)
{
        return gnet_stats_start_copy_compat(skb, type, 0, 0, lock, d);
}

struct gnet_stats_basic
{
        __u64   bytes;
        __u32   packets;
};
struct gnet_stats_basic_packed
{
        __u64   bytes;
        __u32   packets;
}; // __attribute__ ((packed));

int
gnet_stats_copy_basic(struct gnet_dump *d, struct gnet_stats_basic_packed *b)
{
        if (d->compat_tc_stats) {
                d->tc_stats.bytes = b->bytes;
                d->tc_stats.packets = b->packets;
        }

        if (d->tail) {
                struct gnet_stats_basic sb;

                memset(&sb, 0, sizeof(sb));
                sb.bytes = b->bytes;
                sb.packets = b->packets;
                return gnet_stats_copy(d, TCA_STATS_BASIC, &sb, sizeof(sb));
        }
        return 0;
}

struct gnet_stats_rate_est
{
        __u32   bps;
        __u32   pps;
};

int
gnet_stats_copy_rate_est(struct gnet_dump *d, struct gnet_stats_rate_est *r)
{
        if (d->compat_tc_stats) {
                d->tc_stats.bps = r->bps;
                d->tc_stats.pps = r->pps;
        }

        if (d->tail)
                return gnet_stats_copy(d, TCA_STATS_RATE_EST, r, sizeof(*r));

        return 0;
}

struct gnet_stats_queue
{
        __u32   qlen;
        __u32   backlog;
        __u32   drops;
        __u32   requeues;
        __u32   overlimits;
};

/* Action attributes */
enum {
        TCA_ACT_UNSPEC,
        TCA_ACT_KIND,
        TCA_ACT_OPTIONS,
        TCA_ACT_INDEX,
        TCA_ACT_STATS,
        TCA_ACT_PAD,
        TCA_ACT_COOKIE,
        __TCA_ACT_MAX
};

#define TCA_ACT_MAX __TCA_ACT_MAX
#define TCA_OLD_COMPAT (TCA_ACT_MAX+1)

enum {
  TCA_EMATCH_TREE_UNSPEC,
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
  TCA_EMATCH_TREE_HDR,
  TCA_EMATCH_TREE_LIST,
  __TCA_EMATCH_TREE_MAX
};


int
gnet_stats_copy_queue(struct gnet_dump *d, struct gnet_stats_queue *q)
{
        if (d->compat_tc_stats) {
                d->tc_stats.drops = q->drops;
                d->tc_stats.qlen = q->qlen;
                d->tc_stats.backlog = q->backlog;
                d->tc_stats.overlimits = q->overlimits;
        }

        if (d->tail)
                return gnet_stats_copy(d, TCA_STATS_QUEUE, q, sizeof(*q));

        return 0;
}

#define tcf_bstats      common.tcfc_bstats
#define tcf_qstats      common.tcfc_qstats
#define tcf_rate_est    common.tcfc_rate_est
#define tcf_lock        common.tcfc_lock

struct tcf_common {
        struct tcf_common               *tcfc_next;
        u32                             tcfc_index;
        int                             tcfc_refcnt;
        int                             tcfc_bindcnt;
        u32                             tcfc_capab;
        int                             tcfc_action;
//        struct tcf_t                    tcfc_tm;
        struct gnet_stats_basic_packed  tcfc_bstats;
        struct gnet_stats_queue         tcfc_qstats;
        struct gnet_stats_rate_est      tcfc_rate_est;
        spinlock_t                      tcfc_lock;
};

struct tcf_act_hdr {
        struct tcf_common       common;
};

int
gnet_stats_finish_copy(struct gnet_dump *d)
{
        if (d->tail)
                d->tail->nla_len = skb_tail_pointer(d->skb) - (u8 *)d->tail;

        if (d->compat_tc_stats)
                if (gnet_stats_copy(d, d->compat_tc_stats, &d->tc_stats,
                        sizeof(d->tc_stats)) < 0)
                        return -1;

        if (d->compat_xstats && d->xstats) {
                if (gnet_stats_copy(d, d->compat_xstats, d->xstats,
                        d->xstats_len) < 0)
                        return -1;
        }

//        spin_unlock_bh(d->lock);
        return 0;
}

int tcf_action_copy_stats(struct sk_buff *skb, struct tc_action *a,
                          int compat_mode)
{
        int err = 0;
        struct gnet_dump d;
        struct tcf_act_hdr *h = a->priv;

        if (h == NULL)
                goto errout;

        /* compat_mode being true specifies a call that is supposed
         * to add additional backward compatiblity statistic TLVs.
         */
        if (compat_mode) {
                if (a->type == TCA_OLD_COMPAT)
                        err = gnet_stats_start_copy_compat(skb, 0,
                                TCA_STATS, TCA_XSTATS, &h->tcf_lock, &d);
                else
                        return 0;
        } else
                err = gnet_stats_start_copy(skb, TCA_ACT_STATS,
                                            &h->tcf_lock, &d);

        if (err < 0)
                goto errout;

        if (a->ops != NULL && a->ops->get_stats != NULL)
                if (a->ops->get_stats(skb, a) < 0)
                        goto errout;

        if (gnet_stats_copy_basic(&d, &h->tcf_bstats) < 0 ||
            gnet_stats_copy_rate_est(&d, &h->tcf_rate_est) < 0 ||
            gnet_stats_copy_queue(&d, &h->tcf_qstats) < 0)
                goto errout;

        if (gnet_stats_finish_copy(&d) < 0)
                goto errout;

        return 0;

errout:
        return -1;
}

int
tcf_action_dump_old(struct sk_buff *skb, struct tc_action *a, int bind, int ref)
{
        int err = -EINVAL;

        if (a->ops == NULL || a->ops->dump == NULL)
                return err;
        return a->ops->dump(skb, a, bind, ref);
}

int
tcf_action_dump_1(struct sk_buff *skb, struct tc_action *a, int bind, int ref)
{
        int err = -EINVAL;
        unsigned char *b = skb_tail_pointer(skb);
        struct nlattr *nest;

        if (a->ops == NULL || a->ops->dump == NULL)
                return err;

        NLA_PUT_STRING(skb, TCA_KIND, a->ops->kind);
        if (tcf_action_copy_stats(skb, a, 0))
                goto nla_put_failure;
        nest = nla_nest_start(skb, TCA_OPTIONS);
        if (nest == NULL)
                goto nla_put_failure;
        if ((err = tcf_action_dump_old(skb, a, bind, ref)) > 0) {
                nla_nest_end(skb, nest);
                return err;
        }

nla_put_failure:
        nlmsg_trim(skb, b);
        return -1;
}

int
tcf_action_dump(struct sk_buff *skb, struct tc_action *act, int bind, int ref)
{
        struct tc_action *a;
        int err = -EINVAL;
        struct nlattr *nest;

        while ((a = act) != NULL) {
                act = a->next;
                nest = nla_nest_start(skb, a->order);
                if (nest == NULL)
                        goto nla_put_failure;
                err = tcf_action_dump_1(skb, a, bind, ref);
                if (err < 0)
                        goto errout;
                nla_nest_end(skb, nest);
        }

        return 0;

nla_put_failure:
        err = -EINVAL;
errout:
        nla_nest_cancel(skb, nest);
        return err;
}

struct tcf_ext_map
{
        int action;
        int police;
};

int tcf_exts_dump(struct sk_buff *skb, struct tcf_exts *exts,
                  const struct tcf_ext_map *map)
{
#ifdef CONFIG_NET_CLS_ACT
        if (map->action && exts->action) {
                /*
                 * again for backward compatible mode - we want
                 * to work with both old and new modes of entering
                 * tc data even if iproute2  was newer - jhs
                 */
                struct nlattr *nest;

                if (exts->action->type != TCA_OLD_COMPAT) {
                        nest = nla_nest_start(skb, map->action);
                        if (nest == NULL)
                                goto nla_put_failure;
                        if (tcf_action_dump(skb, exts->action, 0, 0) < 0)
                                goto nla_put_failure;
                        nla_nest_end(skb, nest);
                } else if (map->police) {
                        nest = nla_nest_start(skb, map->police);
                        if (nest == NULL)
                                goto nla_put_failure;
                        if (tcf_action_dump_old(skb, exts->action, 0, 0) < 0)
                                goto nla_put_failure;
                        nla_nest_end(skb, nest);
                }
        }
#endif
        return 0;
nla_put_failure: // __attribute__ ((unused))
        return -1;
}

static inline struct tcf_ematch * tcf_em_get_match(struct tcf_ematch_tree *tree,
                                                   int index)
{
        return &tree->matches[index];
}

int tcf_em_tree_dump(struct sk_buff *skb, struct tcf_ematch_tree *tree, int tlv)
{
        int i;
        u8 *tail;
        struct nlattr *top_start;
        struct nlattr *list_start;

        top_start = nla_nest_start(skb, tlv);
        if (top_start == NULL)
                goto nla_put_failure;

        NLA_PUT(skb, TCA_EMATCH_TREE_HDR, sizeof(tree->hdr), &tree->hdr);

        list_start = nla_nest_start(skb, TCA_EMATCH_TREE_LIST);
        if (list_start == NULL)
                goto nla_put_failure;

        tail = skb_tail_pointer(skb);
        for (i = 0; i < tree->hdr.nmatches; i++) {
                struct nlattr *match_start = (struct nlattr *)tail;
                struct tcf_ematch *em = tcf_em_get_match(tree, i);
                struct tcf_ematch_hdr em_hdr = {
                        .kind = em->ops ? em->ops->kind : TCF_EM_CONTAINER,
                        .matchid = em->matchid,
                        .flags = em->flags
                };

                NLA_PUT(skb, i+1, sizeof(em_hdr), &em_hdr);

                if (em->ops && em->ops->dump) {
                        if (em->ops->dump(skb, em) < 0)
                                goto nla_put_failure;
                } else if (tcf_em_is_container(em) || tcf_em_is_simple(em)) {
                        u32 u = em->data;
                        nla_put_nohdr(skb, sizeof(u), &u);
                } else if (em->datalen > 0)
                        nla_put_nohdr(skb, em->datalen, (void *) em->data);

                tail = skb_tail_pointer(skb);
                match_start->nla_len = tail - (u8 *)match_start;
        }

        nla_nest_end(skb, list_start);
        nla_nest_end(skb, top_start);

        return 0;

nla_put_failure:
        return -1;
}

enum {
	TCA_BASIC_UNSPEC,
	TCA_BASIC_CLASSID,
	TCA_BASIC_EMATCHES,
	TCA_BASIC_ACT,
	TCA_BASIC_POLICE,
	TCA_BASIC_PCNT,
	TCA_BASIC_PAD,
	__TCA_BASIC_MAX
};

static const struct tcf_ext_map basic_ext_map = {
        .action = TCA_BASIC_ACT,
        .police = TCA_BASIC_POLICE
};

static int basic_dump(struct tcf_proto *tp, unsigned long fh,
                      struct sk_buff *skb, struct tcmsg *t)
{
        struct basic_filter *f = (struct basic_filter *) fh;
        struct nlattr *nest;

        if (f == NULL)
                return skb->len;

        t->tcm_handle = f->handle;

        nest = nla_nest_start(skb, TCA_OPTIONS);
        if (nest == NULL)
                goto nla_put_failure;

        if (f->res.classid)
                NLA_PUT_U32(skb, TCA_BASIC_CLASSID, f->res.classid);

        if (tcf_exts_dump(skb, &f->exts, &basic_ext_map) < 0 ||
            tcf_em_tree_dump(skb, &f->ematches, TCA_BASIC_EMATCHES) < 0)
                goto nla_put_failure;

        nla_nest_end(skb, nest);
        return skb->len;

nla_put_failure:
        nla_nest_cancel(skb, nest);
        return -1;
}

///////////////////////////////////////////////////////////////////////////////

static int tcf_fill_node(struct sk_buff *skb, struct tcf_proto *tp,
			 unsigned long fh, u32 pid, u32 seq, u16 flags, int event)
{
	struct tcmsg *tcm;
	struct nlmsghdr  *nlh;
	unsigned char *b = skb_tail_pointer(skb);

        #define MARK(num) printf("got here %d\n", num);

	nlh = NLMSG_NEW(skb, pid, seq, event, sizeof(*tcm), flags);
	tcm = NLMSG_DATA(nlh);
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm__pad1 = 0;
	tcm->tcm__pad1 = 0;
//	tcm->tcm__pad2 = 0; FIX!
	tcm->tcm_ifindex = qdisc_dev(tp->q)->ifindex;
	tcm->tcm_parent = tp->classid;
	tcm->tcm_info = TC_H_MAKE(tp->prio, tp->protocol);
	NLA_PUT_STRING(skb, TCA_KIND, tp->ops->kind);
	tcm->tcm_handle = fh;
	if (RTM_DELTFILTER != event) {
		tcm->tcm_handle = 0;
		if (tp->ops->dump && tp->ops->dump(tp, fh, skb, tcm) < 0)
			goto nla_put_failure;
	}
	nlh->nlmsg_len = skb_tail_pointer(skb) - b;
	return skb->len;

nlmsg_failure:
nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

#include "distinctions.h"
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
	struct sk_buff skb = {0};
        skb.data = malloc(1024 * 1024);
        skb.head = skb.data;
        skb.end = 1024 * 1024;
        skb.tail = 0;
        skb.data_len = 0; // only for nonlinear
        skb.len = 0;

        struct net_device nd = { .ifindex = 0 };
        struct netdev_queue nd_q = { .dev = &nd };
        struct Qdisc qdisc = { .dev_queue = &nd_q };
	struct tcf_proto_ops ops = { .dump = basic_dump };
	struct tcf_proto tp = { .ops = &ops, .q = &qdisc };

        int pos = 0;

	unsigned long fh;
	u32 pid, seq;
	u16 flags;
	int event;
	int ifindex;
	nd.ifindex = ifindex;

#define INIT_INPUT(num)
#define GENERATE_OUTPUT(num) struct sk_buff skb ## num = skb; if (tcf_fill_node(&skb ## num, &tp, fh, pid, seq, flags, event)) return 1;
#define OUTPUTS_EQUAL(num1, num2) (skb ## num1.len == skb ## num2.len && !memcmp(skb ## num1.data, skb ## num2.data, skb ## num1.len))

	CHECK_1_BITS_LEAKAGE()

        return 0;
}

// #include "base64.h"

// int main() {
//         unsigned long fh = 0;
// 	u32 pid = 0, seq = 0;
// 	u16 flags = 0;
// 	int event = 0;

// 	char buf[sizeof(fh) + sizeof(pid) + sizeof(seq) + sizeof(flags) + sizeof(event)];
// 	memcpy(buf, &fh, sizeof(fh));
//         int pos = sizeof(fh);
// #define ENCODE(var) memcpy(buf + pos, &var, sizeof(var)); pos += sizeof(var);
//         ENCODE(pid);
//         ENCODE(seq);
//         ENCODE(flags);
//         ENCODE(event);

// 	int enc_len = Base64encode_len(sizeof(buf));
// 	char *encoded = malloc(enc_len);
// 	int res = Base64encode(encoded, buf, sizeof(buf));
//         printf("{\n  \"PUBLIC\": \"");
// 	for (int i = 0; i < res; i++) {
// 		printf("%c", encoded[i]);
// 	}
//         printf("\",\n  \"SECRET\": \"MDAwMA==\"\n}\n");
// 	printf("\npredicted len: %d, actual: %d\n", enc_len, res);
// }
