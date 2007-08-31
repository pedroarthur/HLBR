#include "decode_udp.h"
#include "decode_ip.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//#define DEBUG

extern GlobalVars	Globals;

int	IPDecoderID;

/***************************************
* Apply the udp decoding
****************************************/
void* DecodeUDP(int PacketSlot){
	UDPData*		data;
	IPData*			ip_data;
	unsigned char	ip_proto;
	PacketRec*		p;
	
#ifdef DEBUGPATH
	printf("In DecodeUDP\n");
#endif

#ifdef DEBUG
	printf("Decoding UDP Header\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&ip_data)){
		printf("Failed to get IP header data\n");
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

/*************************************
* Set up the decoder
*************************************/
int InitDecoderUDP(){
	int DecoderID;

#ifdef DEBUGPATH
	printf("In InitDecoderUDP\n");
#endif
	
	if ((DecoderID=CreateDecoder("UDP"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate UDP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeUDP;
	if (!DecoderAddDecoder(GetDecoderByName("IP"), DecoderID)){
		printf("Failed to Bind UDP Decoder to IPDefrag Decoder\n");
		return FALSE;
	}

	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
