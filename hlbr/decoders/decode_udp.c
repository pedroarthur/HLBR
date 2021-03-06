//#define DEBUG
#include "decode_udp.h"
#include "decode_ip.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>


extern GlobalVars	Globals;

int	IPDecoderID;

/**
 * Apply the UDP decoding.
 */
void* DecodeUDP(int PacketSlot)
{
	UDPData*		data;
	IPData*			ip_data;
	unsigned char	ip_proto;
	PacketRec*		p;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("Decoding UDP Header\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&ip_data)){
		fprintf(stderr, "Failed to get IP header data\n");
		return NULL;
	}

	ip_proto=ip_data->Header->protocol;
	
	if (ip_proto!=IP_PROTO_UDP){
#ifdef DEBUG
		printf("IP doesn't think this is an udp packet %02x\n",ip_proto);
#endif		
		return NULL;
	}
		
	data=malloc(sizeof(UDPData));
	data->Header=(UDPHdr*)(p->RawPacket+p->BeginData);
	p->BeginData+=sizeof(UDPHdr);
	
#ifdef DEBUG
	printf("UDP %u->%u\n",ntohs(data->Header->source), ntohs(data->Header->dest)); 
#endif	

	return data;
}

/**
 * Set up the UDP decoder.
 */
int InitDecoderUDP()
{
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID=CreateDecoder("UDP"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate UDP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeUDP;
	Globals.Decoders[DecoderID].Free=free;
	if (!DecoderAddDecoder(GetDecoderByName("IPDefrag"), DecoderID)){
		fprintf(stderr, "Failed to Bind UDP Decoder to IPDefrag Decoder\n");
		return FALSE;
	}

	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}


#ifdef DEBUG
#undef DEBUG
#endif
