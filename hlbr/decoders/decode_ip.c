#include "decode_ip.h"
#include "decode_ethernet.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#define DEBUG

extern GlobalVars	Globals;

int	EthernetDecoderID;

/***************************************
* Apply the ip decoding
****************************************/
void* DecodeIP(int PacketSlot){
	IPData*			data;
	EthernetData*	edata;
	unsigned short	etype;
	PacketRec*		p;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("Decoding IP Header\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, EthernetDecoderID, (void**)&edata)){
		printf("2Failed to get Ethernet header data\n");
		return NULL;
	}

	etype=ntohs(edata->Header->Type);
	
	if (etype!=ETHERNET_TYPE_IP){
#ifdef DEBUG
		printf("Ethernet doesn't think this is an IP packet %04x\n",etype);
#endif		
		return NULL;
	}
		
	data=malloc(sizeof(IPData));
	data->Header=(IPHdr*)(p->RawPacket+p->BeginData);
	p->BeginData+=(data->Header->ihl*4);
	
#ifdef DEBUG
	printf("IP %s->",inet_ntoa(*(struct in_addr*)&data->Header->saddr));
	printf("%s\n",inet_ntoa(*(struct in_addr*)&data->Header->daddr));
#endif	

	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderIP(){
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID=CreateDecoder("IP"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate IP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeIP;
	if (!DecoderAddDecoder(GetDecoderByName("Ethernet"), DecoderID)){
		printf("Failed to Bind IP Decoder to Ethernet Decoder\n");
		return FALSE;
	}

	EthernetDecoderID=GetDecoderByName("Ethernet");

	return TRUE;
}
