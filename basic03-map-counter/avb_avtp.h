#ifndef __AVB_AVTP_H__
#define __AVB_AVTP_H__


#define MAX_SAMPLE_VALUE ((1U << ((sizeof(int32_t)*8)-1))-1)

#define IEEE_61883_IIDC_SUBTYPE 0x0

#define ETHER_TYPE_AVTP		0x22f0

#define ETH_ALEN   6 /* Size of Ethernet address */

typedef struct {
	/* Destination MAC address. */
	__u8 h_dest [ETH_ALEN];
	/* Destination MAC address. */
	__u8 h_source [ETH_ALEN];
	/* VLAN */
	__u8 h_vlan[4];
	/* Protocol ID. */
	__u8 h_protocol[2];
} eth_headerQ;

typedef struct {
	__u8 subtype_cd;
	__u8 ts_gw_sid_valid_version;
	__u8 seq_number;
	__u8 ts_uncertain_res;
	__u8 stream_id[8];
	__u8 timestamp[4];
	__u8 gateway_info[4];
	__u8 length[2];
} seventeen22_header;

/* 61883 CIP with SYT Field */
typedef struct {
	__u8 packet_channel_format_tag;
	__u8 app_control_packet_tcode;
	__u8 source_id_reserved0;
	__u8 data_block_size;
	__u8 reserved1_sph_qpadding_count_fracnum;
	__u8 data_block_continuity;
	__u8 format_id_eoh;
	__u8 format_dependent_field:8;
	__u8 syt[2];
} six1883_header;

#endif