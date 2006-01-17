#include "decode_tcp_stream.h"
#include "decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/session.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#define DEBUG

extern GlobalVars	Globals;

int	TCPDecoderID;

/***************************************
* Apply the tcp stream decoding
****************************************/
void* DecodeTCPStream(int PacketSlot){
	TCPStreamData*	data;
	TCPData*		tcp_data;
	SessionRec*		session;
	PacketRec*		p;
	
	
#ifdef DEBUGPATH
	printf("In DecodeTCPStream\n");
#endif

#ifdef DEBUG
	printf("Decoding TCP Stream\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&tcp_data)){
		printf("Failed to get TCP header data\n");
		return NULL;
	}
		
	data=malloc(sizeof(TCPStreamData));
	data->SPort=ntohs(tcp_data->Header->source);
	data->DPort=ntohs(tcp_data->Header->dest);
	
	session=GetSession(p->PacketSlot);
	if (!session){
		printf("Couldn't get session\n");
		return NULL;
	}

#ifdef DEBUG	
	if (session->PacketCount==1){
		printf("+++++++++++++++++++++First Packet in the TCP session\n");
		if (!(tcp_data->Header->syn && !tcp_data->Header->ack && !tcp_data->Header->rst)){
			printf("^^^^^^^^^^^^^^^^^^^^^^Session didn't begin with a SYN\n");	
			if (tcp_data->Header->syn)printf("S"); else printf("*");
			if (tcp_data->Header->ack)printf("A"); else printf("*");
			if (tcp_data->Header->rst)printf("R"); else printf("*");
			printf("\n");
		}
	}else{
		printf("Packet count is %u\n",session->PacketCount);
	}
#endif	
	
	
#ifdef DEBUG
	printf("TCP Stream %u->%u\n",ntohs(tcp_data->Header->source), ntohs(tcp_data->Header->dest)); 
#endif	

	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderTCPStream(){
	int DecoderID;

#ifdef DEBUGPATH
	printf("In InitDecoderTCPStream\n");
#endif
	
	if ((DecoderID=CreateDecoder("TCPStream"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate TCPStream Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeTCPStream;
	if (!DecoderAddDecoder(GetDecoderByName("TCP"), DecoderID)){
		printf("Failed to Bind TCP Stream Decoder to TCP Decoder\n");
		return FALSE;
	}

	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
