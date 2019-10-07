/*
Copyright (c) 2013 Katja Rohloff <katja.rohloff@uni-jena.de>

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#define ETHERNET_HEADER_SIZE (18)
#define SEVENTEEN22_HEADER_PART1_SIZE (4)
#define STREAM_ID_SIZE (8)
#define SEVENTEEN22_HEADER_PART2_SIZE (10)
#define SIX1883_HEADER_SIZE (10)
#define HEADER_SIZE (ETHERNET_HEADER_SIZE		\
			+ SEVENTEEN22_HEADER_PART1_SIZE \
			+ STREAM_ID_SIZE		\
			+ SEVENTEEN22_HEADER_PART2_SIZE \
			+ SIX1883_HEADER_SIZE)
#define SAMPLES_PER_SECOND (48000)
#define SAMPLES_PER_FRAME (6)
#define CHANNELS (2)
#define SAMPLE_SIZE (4)
#define DEFAULT_RINGBUFFER_SIZE (32768)
#define MAX_SAMPLE_VALUE ((1U << ((sizeof(int32_t) * 8) -1)) -1)

struct ethernet_header{
	u_char dst[6];
	u_char src[6];
	u_char stuff[4];
	u_char type[2];
};

u_char glob_ether_type[] = { 0x22, 0xf0 };
static jack_port_t** outputports;
static jack_default_audio_sample_t** out;
jack_ringbuffer_t* ringbuffer;
jack_client_t* client;
volatile int ready = 0;
unsigned char glob_station_addr[] = { 0, 0, 0, 0, 0, 0 };
unsigned char glob_stream_id[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
/* IEEE 1722 reserved address */
unsigned char glob_dest_addr[] = { 0x91, 0xE0, 0xF0, 0x00, 0x0e, 0x80 };
struct pollfd *avtp_transport_socket_fds;


int receive_avtp_packet(  )
{
    char stream_packet[BUFLEN];

	uint32_t* mybuf;
	uint32_t frame[CHANNELS];
	jack_default_audio_sample_t jackframe[CHANNELS];
	int cnt;
	static int total;

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
                
                
                
                
                
                /*
                 *  Deinterleave and Store samples
                 */
                mybuf = (uint32_t*) (stream_packet + HEADER_SIZE);

                for(int i = 0; i < SAMPLES_PER_FRAME * CHANNELS; i+=CHANNELS) {

                    memcpy(&frame[0], &mybuf[i], sizeof(frame));

                    for(int j = 0; j < CHANNELS; j++) {

                        frame[j] = ntohl(frame[j]);   /* convert to host-byte order */
                        frame[j] &= 0x00ffffff;       /* ignore leading label */
                        frame[j] <<= 8;               /* left-align remaining PCM-24 sample */

                        jackframe[j] = ((int32_t)frame[j])/(float)(MAX_SAMPLE_VALUE);
                    }

                }
                
                return adjust_packet_time_ns -1000;
            }
        }
    }
    return 0;
}




