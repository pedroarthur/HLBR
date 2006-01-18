#include "decode_tcp.h"
#include "decode_ip.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//#define DEBUG

extern GlobalVars	Globals;

int	IPDecoderID;

/***************************************
* Apply the tcp decoding
****************************************/
void* DecodeTCP(int PacketSlot){
	TCPData*		data;
	IPData*			ip_data;
	unsigned char	ip_proto;
	PacketRec*		p;
	
#ifdef DEBUGPATH
	printf("In DecodeTCP\n");
#endif

#ifdef DEBUG
	printf("Decoding TCP Header\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&ip_data)){
		printf("Failed to get IP header data\n");
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
	p->BeginData+=(data->Header->doff*4);
	data->Data=(unsigned char*)(p->RawPacket+p->BeginData);
	data->DataLen=p->PacketLen-((int)(data->Data)-(int)(p->RawPacket));
	
#ifdef DEBUG
	printf("In PacketSlot %i TCP %u->%u\n",PacketSlot, ntohs(data->Header->source), ntohs(data->Header->dest)); 
#endif	

	AssignSessionTCP(PacketSlot, (void*)data);

	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderTCP(){
	int DecoderID;

#ifdef DEBUGPATH
	printf("In InitDecoderTCP\n");
#endif
	
	if ((DecoderID=CreateDecoder("TCP"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate TCP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeTCP;
	if (!DecoderAddDecoder(GetDecoderByName("IP"), DecoderID)){
		printf("Failed to Bind TCP Decoder to IPDefrag Decoder\n");
		return FALSE;
	}

	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}