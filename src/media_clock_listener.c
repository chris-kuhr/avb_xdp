/*
Copyright (C) 2016-2019 Christoph Kuhr

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "media_clock_listener.h"

#define NUM_TS 10000000

extern int errno;
static uint64_t last_packet_time_ns = 0;
uint64_t timestamps[NUM_TS];
int ts_cnt =0;

uint64_t avtp_mcl_wait_for_rx_ts( FILE* filepointer, avb_driver_state_t **avb_ctx,
                                            struct sockaddr_in **si_other_avb,
                                            struct pollfd **avtp_transport_socket_fds,
                                            int packet_num )
{
    char stream_packet[BUFLEN];

//    struct cmsghdr {
//        socklen_t     cmsg_len;     // data byte count, including hdr
//        int           cmsg_level;   // originating protocol
//        int           cmsg_type;    // protocol-specific type
//        // followed by unsigned char cmsg_data[];
//    };
//
//    struct msghdr {
//        void         *msg_name;       // optional address
//        socklen_t     msg_namelen;    // size of address
//        struct iovec *msg_iov;        // scatter/gather array
//        size_t        msg_iovlen;     // # elements in msg_iov
//        void         *msg_control;    // ancillary data, see below
//        size_t        msg_controllen; // ancillary data buffer len
//        int           msg_flags;      // flags on received message
//    };

    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sockaddr_ll remote;
    struct iovec sgentry;
    struct {
        struct cmsghdr cm;
        char control[256];
    } control;

    memset( &msg, 0, sizeof( msg ));
    msg.msg_iov = &sgentry;
    msg.msg_iovlen = 1;
    sgentry.iov_base = stream_packet;
    sgentry.iov_len = BUFLEN;

    memset( &remote, 0, sizeof(remote));
    msg.msg_name = (caddr_t) &remote;
    msg.msg_namelen = sizeof( remote );
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(control);


    
    /*
     *  Check eth type 
     */
    if( ethertype = 0x22f0 )
    {
        /*
         *  Check destination mac
         */
        if( memcmp(socket_dst_mac, packet_dst_mac ethertype, 6 )
        {
            /*
             *  Check stream id
             */
            if( // Compare Stream IDs
                (glob_stream_id[0] == (uint8_t) stream_packet[18]) &&
                (glob_stream_id[1] == (uint8_t) stream_packet[19]) &&
                (glob_stream_id[2] == (uint8_t) stream_packet[20]) &&
                (glob_stream_id[3] == (uint8_t) stream_packet[21]) &&
                (glob_stream_id[4] == (uint8_t) stream_packet[22]) &&
                (glob_stream_id[5] == (uint8_t) stream_packet[23]) &&
                (glob_stream_id[6] == (uint8_t) stream_packet[24]) &&
                (glob_stream_id[7] == (uint8_t) stream_packet[25])
            ){
                /*
                 *  Count Packets with Sequence Id untill period size, then 
                 *  rewrite and pass packet
                 */
                uint64_t adjust_packet_time_ns = 0;
                uint64_t packet_arrival_time_ns = 0;
                uint64_t rx_int_to_last_packet_ns = 0;

                // Packet Arrival Time from Device
                cmsg = CMSG_FIRSTHDR(&msg);
                while( cmsg != NULL ) {
                    if( cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING ) {
                        struct timespec *ts_device, *ts_system;
                        ts_system = ((struct timespec *) CMSG_DATA(cmsg)) + 1;
                        ts_device = ts_system + 1;
                        packet_arrival_time_ns =  (ts_device->tv_sec*1000000000LL + ts_device->tv_nsec);
                        if( ts_cnt < NUM_TS )
                            timestamps[ts_cnt++] = packet_arrival_time_ns;
                        break;
                    }
                    cmsg = CMSG_NXTHDR(&msg,cmsg);
                }

                rx_int_to_last_packet_ns = packet_arrival_time_ns - last_packet_time_ns;
                last_packet_time_ns = packet_arrival_time_ns;

                if( packet_num == (*avb_ctx)->num_packets -1){

                    adjust_packet_time_ns = (uint64_t) ( ( (float)((*avb_ctx)->period_size % 6 ) / (float)(*avb_ctx)->sample_rate ) * 1000000000LL);
                } else {
                    adjust_packet_time_ns = (*avb_ctx)->adjust ? rx_int_to_last_packet_ns : 125000;
                }
                return adjust_packet_time_ns -1000;
            }
        }
    }
    return -1;
}
