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

#include "avb_avtp.h"
#include "common_kern_user.h" /* defines: struct datarec; */


/* - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise..
 */
static __always_inline __u16 parse_ethhdr(struct hdr_cursor *nh,
					void *data_end, eth_headerQ_t **ethhdr)
{
	eth_headerQ_t *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_protocol ; /* network-byte-order */
}

static __always_inline __u8 parse_1722hdr(struct hdr_cursor *nh,
					void *data_end, seventeen22_header_t **hdr1722)
{
    seventeen22_header_t *tmp_hdr1722 = nh->pos;
	int hdrsize = sizeof(*tmp_hdr1722);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*hdr1722 = tmp_hdr1722;

	return tmp_hdr1722->subtype_cd & 0x7F; /* network-byte-order */
}

static __always_inline __u8 parse_61883hdr(struct hdr_cursor *nh,
					void *data_end, six1883_header_t **hdr61883)
{
	six1883_header_t *tmp_hdr61883 = nh->pos;
	int hdrsize = sizeof(*tmp_hdr61883);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*hdr61883 = tmp_hdr61883;

	return tmp_hdr61883->data_block_size; /* network-byte-order */
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
    __u8 listen_dst_mac[6] =     {0x00,0x00,0x00,0x00,0x00,0x00};
    __u8 listen_stream_id[8] =   {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	eth_headerQ_t *eth;
	struct datarec *rec = NULL;

	struct hdr_cursor nh;
	int nh_type;




    //Start next header cursor position at data start
	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
    if( nh_type == bpf_htons(ETH_P_TSN) ){
        if( __builtin_memcmp(listen_dst_mac, eth->h_dest, 6 ) == 0 ){
            seventeen22_header_t *hdr1722;
            __u8 proto1722 = parse_1722hdr(&nh, data_end, &hdr1722);
            if( bpf_htons(proto1722) == 0x00
                        && __builtin_memcmp(listen_stream_id, hdr1722->stream_id, 8) == 0){ // 1722-AVTP & StreamId



                six1883_header_t *hdr61883;
                //__u8 audioChannels =
                parse_61883hdr(&nh, data_end, &hdr61883);
                __u32 *avtpSamples = (__u32*)nh.pos;

                int samCnt = 0;
                int sampBuf[AUDIO_CHANNELS][6];

                int i,j;
                #pragma unroll
                for(j=0; j<AUDIO_CHANNELS;j++){

                    #pragma unroll
                    for(i=0; i<6*AUDIO_CHANNELS;i+=AUDIO_CHANNELS){
                        __u32 sample = bpf_htonl(avtpSamples[i+j]) & 0x00ffffff;
                        sample <<= 8;
                        sampBuf[j][i] = (int) sample;//(float)((int)sample);///(float)(2);// use tail here
                        samCnt++;
                    }
                }

                //     Lookup in kernel BPF-side return pointer to actual data record
                __u32 key = XDP_PASS;
                rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
                if (!rec) return XDP_ABORTED;

                __builtin_memcpy(&rec->sampleBuffer, sampBuf, sizeof(sampBuf));


                rec->rx_pkt_cnt++;
                if( rec->rx_pkt_cnt % SAMPLEBUF_SIZE == 0 ){
                    rec->accu_rx_timestamp = 0x123456789;
                    return XDP_PASS;
                } else {
                    return XDP_DROP;
                }
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



/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
//struct __sk_buff {
//	__u32 len;
//	__u32 pkt_type;
//	__u32 mark;
//	__u32 queue_mapping;
//	__u32 protocol;
//	__u32 vlan_present;
//	__u32 vlan_tci;
//	__u32 vlan_proto;
//	__u32 priority;
//	__u32 ingress_ifindex;
//	__u32 ifindex;
//	__u32 tc_index;
//	__u32 cb[5];
//	__u32 hash;
//	__u32 tc_classid;
//	__u32 data;
//	__u32 data_end;
//	__u32 napi_id;
//
//	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
//	__u32 family;
//	__u32 remote_ip4;	/* Stored in network byte order */
//	__u32 local_ip4;	/* Stored in network byte order */
//	__u32 remote_ip6[4];	/* Stored in network byte order */
//	__u32 local_ip6[4];	/* Stored in network byte order */
//	__u32 remote_port;	/* Stored in network byte order */
//	__u32 local_port;	/* stored in host byte order */
//	/* ... here. */
//
//	__u32 data_meta;
//	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);




//	__u64 tstamp;




//	__u32 wire_len;
//	__u32 gso_segs;
//	__bpf_md_ptr(struct bpf_sock *, sk);
//};


