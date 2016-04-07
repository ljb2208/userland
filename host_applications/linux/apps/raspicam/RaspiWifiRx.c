/*
Copyright (c) 2012, Broadcom Europe Ltd
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Video deocode demo using OpenMAX IL though the ilcient helper library

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcm_host.h"
#include "ilclient.h"

#include "fec.h"


#include "lib.h"
#include "wifibroadcast.h"
#include "radiotap.h"

#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1450
#define MAX_DATA_OR_FEC_PACKETS_PER_BLOCK 32

#define DEBUG 0
#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)





// this is where we store a summary of the
// information from the radiotap header

typedef struct  {
	int m_nChannel;
	int m_nChannelFlags;
	int m_nRate;
	int m_nAntenna;
	int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;


typedef struct VIDEO_DECODE_STATE_S VIDEO_DECODE_STATE;

struct VIDEO_DECODE_STATE_S {
		OMX_VIDEO_PARAM_PORTFORMATTYPE format;
		OMX_TIME_CONFIG_CLOCKSTATETYPE cstate;
		COMPONENT_T *video_decode , *video_scheduler, *video_render, *clock;
		COMPONENT_T *list[5];
		TUNNEL_T tunnel[4];
		ILCLIENT_T *client;
		unsigned int data_len;
		OMX_BUFFERHEADERTYPE *buf;
		int port_settings_changed;
		int first_packet;
};

static VIDEO_DECODE_STATE state;

int flagHelp = 0;
int param_port = 0;
int param_data_packets_per_block = 8;
int param_fec_packets_per_block = 4;
int param_block_buffers = 1;
int param_packet_length = MAX_USER_PACKET_LENGTH;
wifibroadcast_rx_status_t *rx_status = NULL;
int max_block_num = -1;

void
usage(void)
{
	printf(
	    "(c)2015 befinitiv. Based on packetspammer by Andy Green.  Licensed under GPL2\n"
	    "\n"
	    "Usage: rx [options] <interfaces>\n\nOptions\n"
			"-p <port> Port number 0-255 (default 0)\n"
			"-b <count> Number of data packets in a block (default 8). Needs to match with tx.\n"
	    "-r <count> Number of FEC packets per block (default 4). Needs to match with tx.\n\n"
	    "-f <bytes> Number of bytes per packet (default %d. max %d). This is also the FEC block size. Needs to match with tx\n"
			"-d <blocks> Number of transmissions blocks that are buffered (default 1). This is needed in case of diversity if one adapter delivers data faster than the other. Note that this increases latency\n"
	    "Example:\n"
	    "  iwconfig wlan0 down\n"
	    "  iw dev wlan0 set monitor otherbss fcsfail\n"
	    "  ifconfig wlan0 up\n"
			"  iwconfig wlan0 channel 13\n"
	    "  rx wlan0        Receive raw packets on wlan0 and output the payload to stdout\n"
	    "\n", MAX_USER_PACKET_LENGTH, MAX_USER_PACKET_LENGTH);
	exit(1);
}

typedef struct {
	pcap_t *ppcap;
	int selectable_fd;
	int n80211HeaderLength;
} monitor_interface_t;

typedef struct {
	int block_num;
	packet_buffer_t *packet_buffer_list;
} block_buffer_t;

void open_and_configure_interface(const char *name, int port, monitor_interface_t *interface) {
	struct bpf_program bpfprogram;
	char szProgram[512];
	char szErrbuf[PCAP_ERRBUF_SIZE];
		// open the interface in pcap

	szErrbuf[0] = '\0';
	interface->ppcap = pcap_open_live(name, 2048, 1, -1, szErrbuf);
	if (interface->ppcap == NULL) {
		fprintf(stderr, "Unable to open interface %s in pcap: %s\n",
		    name, szErrbuf);
		exit(1);
	}


	if(pcap_setnonblock(interface->ppcap, 1, szErrbuf) < 0) {
		fprintf(stderr, "Error setting %s to nonblocking mode: %s\n", name, szErrbuf);
	}

	int nLinkEncap = pcap_datalink(interface->ppcap);

	switch (nLinkEncap) {

		case DLT_PRISM_HEADER:
			fprintf(stderr, "DLT_PRISM_HEADER Encap\n");
			interface->n80211HeaderLength = 0x20; // ieee80211 comes after this
			sprintf(szProgram, "radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", port);
			break;

		case DLT_IEEE802_11_RADIO:
			fprintf(stderr, "DLT_IEEE802_11_RADIO Encap\n");
			interface->n80211HeaderLength = 0x18; // ieee80211 comes after this
			sprintf(szProgram, "ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", port);
			break;

		default:
			fprintf(stderr, "!!! unknown encapsulation on %s !\n", name);
			exit(1);

	}

	if (pcap_compile(interface->ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
		puts(szProgram);
		puts(pcap_geterr(interface->ppcap));
		exit(1);
	} else {
		if (pcap_setfilter(interface->ppcap, &bpfprogram) == -1) {
			fprintf(stderr, "%s\n", szProgram);
			fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
		} else {
		}
		pcap_freecode(&bpfprogram);
	}

	interface->selectable_fd = pcap_get_selectable_fd(interface->ppcap);
}


void block_buffer_list_reset(block_buffer_t *block_buffer_list, size_t block_buffer_list_len, int block_buffer_len) {
    int i;
    block_buffer_t *rb = block_buffer_list;

    for(i=0; i<block_buffer_list_len; ++i) {
        rb->block_num = -1;

        int j;
        packet_buffer_t *p = rb->packet_buffer_list;
        for(j=0; j<param_data_packets_per_block+param_fec_packets_per_block; ++j) {
            p->valid = 0;
            p->crc_correct = 0;
            p->len = 0;
            p++;
        }

        rb++;
    }
}

static int video_decode_process(VIDEO_DECODE_STATE *state, const void* input_buffer, size_t input_buffer_len)
{
	int status = 0;
	int remaining = input_buffer_len;
      while(remaining > 0 && (state->buf = ilclient_get_input_buffer(state->video_decode, 130, 1)) != NULL)
      {
         // feed data and wait until we get port settings changed
         unsigned char *dest = state->buf->pBuffer;

         int len = state->buf->nAllocLen-state->data_len;

         if (input_buffer_len < len)
        	 len = input_buffer_len;

         remaining -= len;

         memcpy(dest, input_buffer, len);
         state->data_len += len;
         //state->data_len += fread(dest, 1, state->buf->nAllocLen-state->data_len, in);

         if(state->port_settings_changed == 0 &&
            ((state->data_len > 0 && ilclient_remove_event(state->video_decode, OMX_EventPortSettingsChanged, 131, 0, 0, 1) == 0) ||
             (state->data_len == 0 && ilclient_wait_for_event(state->video_decode, OMX_EventPortSettingsChanged, 131, 0, 0, 1,
                                                       ILCLIENT_EVENT_ERROR | ILCLIENT_PARAMETER_CHANGED, 10000) == 0)))
         {
        	 state->port_settings_changed = 1;

            if(ilclient_setup_tunnel(state->tunnel, 0, 0) != 0)
            {
               status = -7;
               break;
            }

            ilclient_change_component_state(state->video_scheduler, OMX_StateExecuting);

            // now setup tunnel to video_render
            if(ilclient_setup_tunnel(state->tunnel+1, 0, 1000) != 0)
            {
               status = -12;
               break;
            }

            ilclient_change_component_state(state->video_render, OMX_StateExecuting);
         }
         if(!state->data_len)
            break;

         state->buf->nFilledLen = state->data_len;
         state->data_len = 0;

         state->buf->nOffset = 0;
         if(state->first_packet)
         {
        	 state->buf->nFlags = OMX_BUFFERFLAG_STARTTIME;
            state->first_packet = 0;
         }
         else
        	 state->buf->nFlags = OMX_BUFFERFLAG_TIME_UNKNOWN;

         if(OMX_EmptyThisBuffer(ILC_GET_HANDLE(state->video_decode), state->buf) != OMX_ErrorNone)
         {
            status = -6;
            break;
         }
      }

   return 0;
}

void process_payload(uint8_t *data, size_t data_len, int crc_correct, block_buffer_t *block_buffer_list, int adapter_no)
{
    wifi_packet_header_t *wph;
    int block_num;
    int packet_num;
    int i;

    wph = (wifi_packet_header_t*)data;
    data += sizeof(wifi_packet_header_t);
    data_len -= sizeof(wifi_packet_header_t);

    block_num = wph->sequence_number / (param_data_packets_per_block+param_fec_packets_per_block);//if aram_data_packets_per_block+param_fec_packets_per_block would be limited to powers of two, this could be replaced by a logical AND operation

    //debug_print("adap %d rec %x blk %x crc %d len %d\n", adapter_no, wph->sequence_number, block_num, crc_correct, data_len);


    //we have received a block number that exceeds the currently seen ones -> we need to make room for this new block
    //or we have received a block_num that is several times smaller than the current window of buffers -> this indicated that either the window is too small or that the transmitter has been restarted
    int tx_restart = (block_num + 128*param_block_buffers < max_block_num);
    if((block_num > max_block_num || tx_restart) && crc_correct) {
        if(tx_restart) {
						rx_status->tx_restart_cnt++;

            fprintf(stderr, "TX RESTART: Detected blk %x that lies outside of the current retr block buffer window (max_block_num = %x) (if there was no tx restart, increase window size via -d)\n", block_num, max_block_num);


            block_buffer_list_reset(block_buffer_list, param_block_buffers, param_data_packets_per_block + param_fec_packets_per_block);
        }

        //first, find the minimum block num in the buffers list. this will be the block that we replace
        int min_block_num = INT_MAX;
        int min_block_num_idx;
        for(i=0; i<param_block_buffers; ++i) {
            if(block_buffer_list[i].block_num < min_block_num) {
                min_block_num = block_buffer_list[i].block_num;
                min_block_num_idx = i;
            }
        }

        //debug_print("removing block %x at index %i for block %x\n", min_block_num, min_block_num_idx, block_num);

        packet_buffer_t *packet_buffer_list = block_buffer_list[min_block_num_idx].packet_buffer_list;
        int last_block_num = block_buffer_list[min_block_num_idx].block_num;

        if(last_block_num != -1) {
            rx_status->received_block_cnt++;

            //we have both pointers to the packet buffers (to get information about crc and vadility) and raw data pointers for fec_decode
            packet_buffer_t *data_pkgs[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            packet_buffer_t *fec_pkgs[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            uint8_t *data_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            uint8_t *fec_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            int datas_missing = 0, datas_corrupt = 0, fecs_missing = 0, fecs_corrupt = 0;
            int di = 0, fi = 0;


            //first, split the received packets into DATA a FEC packets and count the damaged packets
            i = 0;
            while(di < param_data_packets_per_block || fi < param_fec_packets_per_block) {
                if(di < param_data_packets_per_block) {
                    data_pkgs[di] = packet_buffer_list + i++;
                    data_blocks[di] = data_pkgs[di]->data;
                    if(!data_pkgs[di]->valid)
                        datas_missing++;
                    if(data_pkgs[di]->valid && !data_pkgs[di]->crc_correct)
                        datas_corrupt++;
                    di++;
                }

                if(fi < param_fec_packets_per_block) {
                    fec_pkgs[fi] = packet_buffer_list + i++;
                    if(!fec_pkgs[fi]->valid)
                        fecs_missing++;

                    if(fec_pkgs[fi]->valid && !fec_pkgs[fi]->crc_correct)
                        fecs_corrupt++;

                    fi++;
                }
            }

            const int good_fecs_c = param_fec_packets_per_block - fecs_missing - fecs_corrupt;
            const int datas_missing_c = datas_missing;
            const int datas_corrupt_c = datas_corrupt;
            const int fecs_missing_c = fecs_missing;
            const int fecs_corrupt_c = fecs_corrupt;

            int good_fecs = good_fecs_c;
            //the following three fields are infos for fec_decode
            unsigned int fec_block_nos[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            unsigned int erased_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            unsigned int nr_fec_blocks = 0;


#if DEBUG
            if(datas_missing_c + datas_corrupt_c > good_fecs_c) {
                int x;

                for(x=0;x<param_data_packets_per_block; ++x) {
                    if(data_pkgs[x]->valid) {
                        if(data_pkgs[x]->crc_correct)
                            fprintf(stderr, "v");
                        else
                            fprintf(stderr, "c");
                    }
                    else
                        fprintf(stderr, "m");
                }

                fprintf(stderr, " ");

                for(x=0;x<param_fec_packets_per_block; ++x) {
                    if(fec_pkgs[x]->valid) {
                        if(fec_pkgs[x]->crc_correct)
                            fprintf(stderr, "v");
                        else
                            fprintf(stderr, "c");
                    }
                    else
                        fprintf(stderr, "m");
                }

                fprintf(stderr, "\n");
            }
#endif

            fi = 0;
            di = 0;

            //look for missing DATA and replace them with good FECs
            while(di < param_data_packets_per_block && fi < param_fec_packets_per_block) {
                //if this data is fine we go to the next
                if(data_pkgs[di]->valid && data_pkgs[di]->crc_correct) {
                    di++;
                    continue;
                }

                //if this DATA is corrupt and there are less good fecs than missing datas we cannot do anything for this data
                if(data_pkgs[di]->valid && !data_pkgs[di]->crc_correct && good_fecs <= datas_missing) {
                    di++;
                    continue;
                }

                //if this FEC is not received we go on to the next
                if(!fec_pkgs[fi]->valid) {
                    fi++;
                    continue;
                }

                //if this FEC is corrupted and there are more lost packages than good fecs we should replace this DATA even with this corrupted FEC
                if(!fec_pkgs[fi]->crc_correct && datas_missing > good_fecs) {
                    fi++;
                    continue;
                }


                if(!data_pkgs[di]->valid)
                    datas_missing--;
                else if(!data_pkgs[di]->crc_correct)
                    datas_corrupt--;

                if(fec_pkgs[fi]->crc_correct)
                    good_fecs--;

                //at this point, data is invalid and fec is good -> replace data with fec
                erased_blocks[nr_fec_blocks] = di;
                fec_block_nos[nr_fec_blocks] = fi;
                fec_blocks[nr_fec_blocks] = fec_pkgs[fi]->data;
                di++;
                fi++;
                nr_fec_blocks++;
            }


            int reconstruction_failed = datas_missing_c + datas_corrupt_c > good_fecs_c;

            if(reconstruction_failed) {
                //we did not have enough FEC packets to repair this block
                rx_status->damaged_block_cnt++;
                fprintf(stderr, "Could not fully reconstruct block %x! Damage rate: %f (%d / %d blocks)\n", last_block_num, 1.0 * rx_status->damaged_block_cnt / rx_status->received_block_cnt, rx_status->damaged_block_cnt, rx_status->received_block_cnt);
                debug_print("Data mis: %d\tData corr: %d\tFEC mis: %d\tFEC corr: %d\n", datas_missing_c, datas_corrupt_c, fecs_missing_c, fecs_corrupt_c);
            }


            //decode data and write it to STDOUT
            fec_decode((unsigned int) param_packet_length, data_blocks, param_data_packets_per_block, fec_blocks, fec_block_nos, erased_blocks, nr_fec_blocks);
            for(i=0; i<param_data_packets_per_block; ++i) {
                payload_header_t *ph = (payload_header_t*)data_blocks[i];

                if(!reconstruction_failed || data_pkgs[i]->valid) {
                    //if reconstruction did fail, the data_length value is undefined. better limit it to some sensible value
                    if(ph->data_length > param_packet_length)
                        ph->data_length = param_packet_length;

                    //write(STDOUT_FILENO, data_blocks[i] + sizeof(payload_header_t), ph->data_length);
                    video_decode_process(&state, data_blocks[i] + sizeof(payload_header_t), ph->data_length);
                }
            }


            //reset buffers
            for(i=0; i<param_data_packets_per_block + param_fec_packets_per_block; ++i) {
                packet_buffer_t *p = packet_buffer_list + i;
                p->valid = 0;
                p->crc_correct = 0;
                p->len = 0;
            }
        }

    block_buffer_list[min_block_num_idx].block_num = block_num;
    max_block_num = block_num;
    }


    //find the buffer into which we have to write this packet
    block_buffer_t *rbb = block_buffer_list;
    for(i=0; i<param_block_buffers; ++i) {
        if(rbb->block_num == block_num) {
            break;
        }
        rbb++;
    }

    //check if we have actually found the corresponding block. this could not be the case due to a corrupt packet
    if(i != param_block_buffers) {
        packet_buffer_t *packet_buffer_list = rbb->packet_buffer_list;
        packet_num = wph->sequence_number % (param_data_packets_per_block+param_fec_packets_per_block); //if retr_block_size would be limited to powers of two, this could be replace by a locical and operation

        //only overwrite packets where the checksum is not yet correct. otherwise the packets are already received correctly
        if(packet_buffer_list[packet_num].crc_correct == 0) {
            memcpy(packet_buffer_list[packet_num].data, data, data_len);
            packet_buffer_list[packet_num].len = data_len;
            packet_buffer_list[packet_num].valid = 1;
            packet_buffer_list[packet_num].crc_correct = crc_correct;
        }
    }

}


void process_packet(monitor_interface_t *interface, block_buffer_t *block_buffer_list, int adapter_no) {
		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 payloadBuffer[MAX_PACKET_LENGTH];
		u8 *pu8Payload = payloadBuffer;
		int bytes;
		int n;
		int retval;
		int u16HeaderLen;

		// receive


		retval = pcap_next_ex(interface->ppcap, &ppcapPacketHeader,
		    (const u_char**)&pu8Payload);

		if (retval < 0) {
			fprintf(stderr, "Socket broken\n");
			fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
			exit(1);
		}

		//if(retval == 0)
		//	fprintf(stderr, "retval = 0\n");

		if (retval != 1)
			return;


		u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

		if (ppcapPacketHeader->len <
		    (u16HeaderLen + interface->n80211HeaderLength))
			return;

		bytes = ppcapPacketHeader->len -
			(u16HeaderLen + interface->n80211HeaderLength);
		if (bytes < 0)
			return;

		if (ieee80211_radiotap_iterator_init(&rti,
		    (struct ieee80211_radiotap_header *)pu8Payload,
		    ppcapPacketHeader->len) < 0)
			return;

		while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

			switch (rti.this_arg_index) {
			case IEEE80211_RADIOTAP_RATE:
				prd.m_nRate = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_CHANNEL:
				prd.m_nChannel =
				    le16_to_cpu(*((u16 *)rti.this_arg));
				prd.m_nChannelFlags =
				    le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
				break;

			case IEEE80211_RADIOTAP_ANTENNA:
				prd.m_nAntenna = (*rti.this_arg) + 1;
				break;

			case IEEE80211_RADIOTAP_FLAGS:
				prd.m_nRadiotapFlags = *rti.this_arg;
				break;

			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				rx_status->adapter[adapter_no].current_signal_dbm = (int8_t)(*rti.this_arg);
				break;

			}
		}
		pu8Payload += u16HeaderLen + interface->n80211HeaderLength;

		if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
			bytes -= 4;


        int checksum_correct = (prd.m_nRadiotapFlags & 0x40) == 0;

		if(!checksum_correct)
			rx_status->adapter[adapter_no].wrong_crc_cnt++;

		rx_status->adapter[adapter_no].received_packet_cnt++;

		if(rx_status->adapter[adapter_no].received_packet_cnt % 1024 == 0) {
			fprintf(stderr, "Signal (card %d): %ddBm\n", adapter_no, rx_status->adapter[adapter_no].current_signal_dbm);
		}

		rx_status->last_update = time(NULL);

        process_payload(pu8Payload, bytes, checksum_correct, block_buffer_list, adapter_no);
}



void status_memory_init(wifibroadcast_rx_status_t *s) {
	s->received_block_cnt = 0;
	s->damaged_block_cnt = 0;
	s->tx_restart_cnt = 0;
	s->wifi_adapter_cnt = 0;

	int i;
	for(i=0; i<MAX_PENUMBRA_INTERFACES; ++i) {
		s->adapter[i].received_packet_cnt = 0;
		s->adapter[i].wrong_crc_cnt = 0;
		s->adapter[i].current_signal_dbm = 0;
	}
}


wifibroadcast_rx_status_t *status_memory_open(void) {
	char buf[128];
	int fd;

	sprintf(buf, "/wifibroadcast_rx_status_%d", param_port);
	fd = shm_open(buf, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

	if(fd < 0) {
		perror("shm_open");
		exit(1);
	}

	if (ftruncate(fd, sizeof(wifibroadcast_rx_status_t)) == -1) {
		perror("ftruncate");
		exit(1);
	}

	void *retval = mmap(NULL, sizeof(wifibroadcast_rx_status_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (retval == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	wifibroadcast_rx_status_t *tretval = (wifibroadcast_rx_status_t*)retval;
	status_memory_init(tretval);

	return tretval;

}


static int video_decode_init(VIDEO_DECODE_STATE *state)
{
	   state->video_decode = NULL;
	   state->video_render = NULL;
	   state->clock = NULL;
	   state->video_scheduler = NULL;

	   int status = 0;
	   state->data_len = 0;

	   memset(state->list, 0, sizeof(state->list));
	   memset(state->tunnel, 0, sizeof(state->tunnel));

	   if((state->client = ilclient_init()) == NULL)
	   {
	      return -3;
	   }

	   if(OMX_Init() != OMX_ErrorNone)
	   {
	      ilclient_destroy(state->client);
	      return -4;
	   }

	   // create video_decode
	   if(ilclient_create_component(state->client, &state->video_decode, "video_decode", ILCLIENT_DISABLE_ALL_PORTS | ILCLIENT_ENABLE_INPUT_BUFFERS) != 0)
	      status = -14;
	   state->list[0] = state->video_decode;

	   // create video_render
	   if(status == 0 && ilclient_create_component(state->client, &state->video_render, "video_render", ILCLIENT_DISABLE_ALL_PORTS) != 0)
	      status = -14;
	   state->list[1] = state->video_render;

	   // create clock
	   if(status == 0 && ilclient_create_component(state->client, &state->clock, "clock", ILCLIENT_DISABLE_ALL_PORTS) != 0)
	      status = -14;
	   state->list[2] = state->clock;

	   memset(&state->cstate, 0, sizeof(state->cstate));
	   state->cstate.nSize = sizeof(state->cstate);
	   state->cstate.nVersion.nVersion = OMX_VERSION;
	   state->cstate.eState = OMX_TIME_ClockStateWaitingForStartTime;
	   state->cstate.nWaitMask = 1;
	   if(state->clock != NULL && OMX_SetParameter(ILC_GET_HANDLE(state->clock), OMX_IndexConfigTimeClockState, &state->cstate) != OMX_ErrorNone)
	      status = -13;

	   // create video_scheduler
	   if(status == 0 && ilclient_create_component(state->client, &state->video_scheduler, "video_scheduler", ILCLIENT_DISABLE_ALL_PORTS) != 0)
	      status = -14;
	   state->list[3] = state->video_scheduler;

	   set_tunnel(state->tunnel, state->video_decode, 131, state->video_scheduler, 10);
	   set_tunnel(state->tunnel+1, state->video_scheduler, 11, state->video_render, 90);
	   set_tunnel(state->tunnel+2, state->clock, 80, state->video_scheduler, 12);

	   // setup clock tunnel first
	   if(status == 0 && ilclient_setup_tunnel(state->tunnel+2, 0, 0) != 0)
	      status = -15;
	   else
	      ilclient_change_component_state(state->clock, OMX_StateExecuting);

	   if(status == 0)
	      ilclient_change_component_state(state->video_decode, OMX_StateIdle);

	   memset(&state->format, 0, sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE));
	   state->format.nSize = sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE);
	   state->format.nVersion.nVersion = OMX_VERSION;
	   state->format.nPortIndex = 130;
	   state->format.eCompressionFormat = OMX_VIDEO_CodingAVC;

	   if(status == 0 &&
	         OMX_SetParameter(ILC_GET_HANDLE(state->video_decode), OMX_IndexParamVideoPortFormat, &state->format) == OMX_ErrorNone &&
	         ilclient_enable_port_buffers(state->video_decode, 130, NULL, NULL, NULL) == 0)
	      {

	         state->port_settings_changed = 0;
	         state->first_packet = 1;

	         ilclient_change_component_state(state->video_decode, OMX_StateExecuting);
	      }

	   return status;
}

static int video_decode_destroy(VIDEO_DECODE_STATE *state)
{
	int status = 0;
    state->buf->nFilledLen = 0;
    state->buf->nFlags = OMX_BUFFERFLAG_TIME_UNKNOWN | OMX_BUFFERFLAG_EOS;

    if(OMX_EmptyThisBuffer(ILC_GET_HANDLE(state->video_decode), state->buf) != OMX_ErrorNone)
       status = -20;

    // wait for EOS from render
    ilclient_wait_for_event(state->video_render, OMX_EventBufferFlag, 90, 0, OMX_BUFFERFLAG_EOS, 0,
                            ILCLIENT_BUFFER_FLAG_EOS, 10000);

    // need to flush the renderer to allow video_decode to disable its input port
    ilclient_flush_tunnels(state->tunnel, 0);

	ilclient_disable_tunnel(state->tunnel);
	ilclient_disable_tunnel(state->tunnel+1);
	ilclient_disable_tunnel(state->tunnel+2);
	ilclient_disable_port_buffers(state->video_decode, 130, NULL, NULL, NULL);
	ilclient_teardown_tunnels(state->tunnel);

	ilclient_state_transition(state->list, OMX_StateIdle);
	ilclient_state_transition(state->list, OMX_StateLoaded);

	ilclient_cleanup_components(state->list);

	OMX_Deinit();

	ilclient_destroy(state->client);
	return 0;

}



int main (int argc, char **argv)
{
   bcm_host_init();

   video_decode_init(&state);

   //return video_decode_test(argv[1]);

   monitor_interface_t interfaces[MAX_PENUMBRA_INTERFACES];
   int num_interfaces = 0;
   int i;

   block_buffer_t *block_buffer_list;

   	while (1) {
   		int nOptionIndex;
   		static const struct option optiona[] = {
   			{ "help", no_argument, &flagHelp, 1 },
   			{ 0, 0, 0, 0 }
   		};
   		int c = getopt_long(argc, argv, "hp:b:d:r:f:",
   			optiona, &nOptionIndex);

   		if (c == -1)
   			break;
   		switch (c) {
   		case 0: // long option
   			break;

   		case 'h': // help
   			usage();

   		case 'p': //port
   			param_port = atoi(optarg);
   			break;

   		case 'b':
   			param_data_packets_per_block = atoi(optarg);
   			break;

   		case 'r':
   			param_fec_packets_per_block = atoi(optarg);
   			break;

   		case 'd':
               param_block_buffers = atoi(optarg);
   			break;

   		case 'f': // MTU
   			param_packet_length = atoi(optarg);
   			break;

   		default:
   			fprintf(stderr, "unknown switch %c\n", c);
   			usage();
   			break;
   		}
   	}

   	if (optind >= argc)
   		usage();


   	if(param_packet_length > MAX_USER_PACKET_LENGTH) {
   		printf("Packet length is limited to %d bytes (you requested %d bytes)\n", MAX_USER_PACKET_LENGTH, param_packet_length);
   		return (1);
   	}

   	fec_init();

   	int x = optind;
   	while(x < argc && num_interfaces < MAX_PENUMBRA_INTERFACES) {
   		open_and_configure_interface(argv[x], param_port, interfaces + num_interfaces);
   		++num_interfaces;
   		++x;
   	}


   //block buffers contain both the block_num as well as packet buffers for a block.
   	block_buffer_list = malloc(sizeof(block_buffer_t) * param_block_buffers);
   	for(i=0; i<param_block_buffers; ++i)
   	{
           block_buffer_list[i].block_num = -1;
           block_buffer_list[i].packet_buffer_list = lib_alloc_packet_buffer_list(param_data_packets_per_block+param_fec_packets_per_block, MAX_PACKET_LENGTH);
   	}


   	rx_status = status_memory_open();
   	rx_status->wifi_adapter_cnt = num_interfaces;

   	for(;;) {
   		fd_set readset;
   		struct timeval to;

   		to.tv_sec = 0;
   		to.tv_usec = 1e5;

   		FD_ZERO(&readset);
   		for(i=0; i<num_interfaces; ++i)
   			FD_SET(interfaces[i].selectable_fd, &readset);

   		int n = select(30, &readset, NULL, NULL, &to);

   		for(i=0; i<num_interfaces; ++i) {
   			if(n == 0)
   				break;

   			if(FD_ISSET(interfaces[i].selectable_fd, &readset)) {
                   process_packet(interfaces + i, block_buffer_list, i);
   			}
   		}

   	}

   	video_decode_destroy(&state);
   	return (0);
}


