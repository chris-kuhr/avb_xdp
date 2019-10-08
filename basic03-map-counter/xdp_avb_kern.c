/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"




/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"




#include "common_kern_user.h" /* defines: struct datarec; */

/* Lesson#1: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") xdp_stats_map2 = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarecCustom),
	.max_entries = XDP_ACTION_MAX,
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **ipheader)
{
	struct iphdr *ip = nh->pos;
	int hdrsize = sizeof(*ip);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ipheader = ip;

	return ip->protocol; /* network-byte-order */
}

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_avtp")
int  xdp_avtp_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	// void *data_end = (void *)(long)ctx->data_end;
	// void *data     = (void *)(long)ctx->data;
	struct datarecCustom *rec;
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;



	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

    if( nh_type == bpf_htons(ETH_P_IP) ){ //ETH_P_TSN = 0x22f0
        struct iphdr *ipheader;
        int ip_proto_type = parse_iphdr(&nh, data_end, &ipheader);

        if( ip_proto_type == bpf_htons(IPPROTO_ICMP) ){
            /* Multiple CPUs can access data record. Thus, the accounting needs to
             * use an atomic operation.
             */
            lock_xadd(&rec->counter, 1);
            /* Assignment#1: Add byte counters
             * - Hint look at struct xdp_md *ctx (copied below)
             *
             * Assignment#3: Avoid the atomic operation
             * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
             */
            /* These keep track of the next header type and iterator pointer */
            if( rec->counter % 32 == 0 ){
                rec->rx_packets = rec->counter;
                return XDP_PASS;
            } else {
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;

}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/
