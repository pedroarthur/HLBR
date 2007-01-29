#include "decode_icmp.h"
#include "decode_ip.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//#define DEBUG

extern GlobalVars	Globals;

int	IPDecoderID;

/***************************************
* Apply the icmp decoding
****************************************/
void* DecodeICMP(int PacketSlot){
	ICMPData*		data;
	IPData*			ip_data;
	unsigned char	ip_proto;
	PacketRec*		p;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("Decoding ICMP Header\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&ip_data)){
		printf("Failed to get IP header data\n");
		return NULL;
	}

	ip_proto=ip_data->Header->protocol;
	
	if (ip_proto!=IP_PROTO_ICMP){
#ifdef DEBUG
		printf("IP doesn't think this is an icmp packet %02x\n",ip_proto);
#endif		
		return NULL;
	}
		
	data=malloc(sizeof(ICMPData));
	data->Header=(ICMPHdr*)(p->RawPacket+p->BeginData);
	p->BeginData+=sizeof(ICMPHdr);
	
#ifdef DEBUG
	printf("ICMP Type %u Code %u\n",data->Header->type, data->Header->code); 
#endif	

	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderICMP(){
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID=CreateDecoder("ICMP"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate ICMP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeICMP;
	if (!DecoderAddDecoder(GetDecoderByName("IP"), DecoderID)){
		printf("Failed to Bind ICMP Decoder to IPDefrag Decoder\n");
		return FALSE;
	}

	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
