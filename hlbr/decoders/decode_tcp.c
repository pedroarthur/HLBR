//#define DEBUG
#include "decode_tcp.h"
#include "decode_ip.h"
#include "decode_ip_defrag.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>


extern GlobalVars	Globals;

int	IPDecoderID;
int	IPDefragDecoderID;

unsigned short sendian (unsigned short val) {
	return ((val & 0xFF00) >> 8) + ((val & 0x00FF) << 8);
}

/**
 * Apply the TCP decoding.
 */
void* DecodeTCP(int PacketSlot) {
	TCPData*		data;

	IPData*			ip_data;
	IPDefragData*		ipd_data;
	unsigned char		ip_proto;

	PacketRec*		p;

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&ip_data)){
		fprintf(stderr, "Failed to get IP header data\n");
		return NULL;
	}

	ip_proto=ip_data->Header->protocol;

	if (ip_proto!=IP_PROTO_TCP){
#ifdef DEBUG
		printf("IP doesn't think this is a tcp packet %02x\n",ip_proto);
#endif
		return NULL;
	}

	data=malloc(sizeof(TCPData));
	data->Header=(TCPHdr*)(p->RawPacket+p->BeginData);

	if (!GetDataByID(PacketSlot, IPDefragDecoderID, (void**)&ipd_data)) {
		printf("Failed to get IPDefrag data\n");
		free(data);
		return NULL;
	}

	if (ipd_data->IsRebuilt) {
		int i;
		unsigned short *tcph = (unsigned short *) p->RawPacket+p->BeginData/2;

		unsigned int check = sendian(ip_data->Header->saddr >> 16) +
		sendian(ip_data->Header->saddr & 0x0000FFFF) +
		sendian(ip_data->Header->daddr >> 16) +
		sendian(ip_data->Header->daddr & 0x0000FFFF) +
		0x0006 +
		(sendian(ip_data->Header->tot_len) - ip_data->Header->ihl * 4);

		data->Header->check = 0;

		for (i = 0 ; i < (p->PacketLen - p->BeginData) / 2 - 1 ; i++) {
			check += sendian(tcph[i]);
		}

		if ((p->PacketLen - p->BeginData) % 2)
			check += sendian(tcph[i] & 0xFF00);
		else
			check += sendian(tcph[i]);

		data->Header->check = 0xFFFF - sendian(check >> 16) - sendian(check) & 0x0000FFFF;
	}

	p->BeginData+=(data->Header->doff*4);
	data->Data=(unsigned char*)(p->RawPacket+p->BeginData);
	data->DataLen=p->PacketLen-((int)(data->Data)-(int)(p->RawPacket));

#ifdef DEBUG
	printf("In PacketSlot %i TCP %u->%u\n",PacketSlot, ntohs(data->Header->source), ntohs(data->Header->dest));
#endif

#ifdef TCP_STREAM_REASSEMBLY
	AssignSessionTCP(PacketSlot, (void*)data);
#endif

	return data;
}

/**
 * Set up the TCP decoder.
 */
int InitDecoderTCP() {
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID=CreateDecoder("TCP"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate TCP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeTCP;
	Globals.Decoders[DecoderID].Free=free;

	if (!DecoderAddDecoder(GetDecoderByName("IPDefrag"), DecoderID)){
		fprintf(stderr, "Failed to Bind TCP Decoder to IPDefrag Decoder\n");
		return FALSE;
	}

	IPDefragDecoderID = GetDecoderByName("IPDefrag");
	IPDecoderID = GetDecoderByName("IP");

	return TRUE;
}

#ifdef DEBUG
#undef DEBUG
#endif
