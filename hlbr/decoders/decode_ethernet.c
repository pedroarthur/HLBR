#include "decode_ethernet.h"
#include "decode_interface.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//#define DEBUG

extern GlobalVars	Globals;

/***************************************
* Apply the Ethernet decoding
****************************************/
void* DecodeEthernet(int PacketSlot){
	InterfaceRec*	r;
	EthernetData*	data;
	PacketRec*		p;
	
	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	/*grab the interface to check the type*/
	/*The interface record is always the first on the stack*/
	r=((InterfaceData*)(p->DecoderInfo[0].Data))->r;
	
	if (r->Proto!=PACKET_PROTO_ETHERNET){
#ifdef DEBUG
		printf("This isn't an ethernet interface\n");
#endif			
		return NULL;
	}

	data=malloc(sizeof(EthernetData));
	data->Header=(EtherHdr*)p->RawPacket;
	p->BeginData=sizeof(EtherHdr);
	
	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderEthernet(){
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID=CreateDecoder("Ethernet"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate Ethernet Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeEthernet;
	Globals.Decoders[DecoderID].Free=free;
	if (!DecoderAddDecoder(GetDecoderByName("Interface"), DecoderID)){
		printf("Failed to Bind Ethernet Decoder to Interface Decoder\n");
		return FALSE;
	}

	return TRUE;
}
