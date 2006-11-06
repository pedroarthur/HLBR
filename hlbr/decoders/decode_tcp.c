#include "decode_tcp.h"
#include "decode_ip.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//#define DEBUG

extern GlobalVars	Globals;

int	IPDecoderID;

/**
 * Apply the TCP decoding
 */
void* DecodeTCP(int PacketSlot)
{
	TCPData*	data;
	IPData*		ip_data;
	unsigned char	ip_proto;
	PacketRec*	p;
	
	DEBUGPATH;

	p = &Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&ip_data)) {
		PRINTERROR("Failed to get IP header data\n");
		return NULL;
	}

	ip_proto = ip_data->Header->protocol;
	
	if (ip_proto != IP_PROTO_TCP) {
		DBG( PRINTERROR1("IP doesn't think this is a tcp packet %02x\n",ip_proto) );
		return NULL;
	}
	
	data = malloc(sizeof(TCPData));
	data->Header = (TCPHdr*)(p->RawPacket+p->BeginData);
	p->BeginData += (data->Header->doff*4);
	data->Data = (unsigned char*)(p->RawPacket+p->BeginData);
	data->DataLen = p->PacketLen-((int)(data->Data)-(int)(p->RawPacket));
	
	DBG( PRINTERROR3("In PacketSlot %i TCP %u->%u\n",PacketSlot, ntohs(data->Header->source), ntohs(data->Header->dest)) ); 

	// Assigns a session structure (PortPair) for this packet
	// this will enable the stream tests, in further decoders.
	AssignSessionTCP(PacketSlot, (void*)data);

	return data;
}

/**
 * Set up the TCP decoder
 */
int InitDecoderTCP()
{
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID = CreateDecoder("TCP")) == DECODER_NONE) {
		DBG( PRINTERROR("Couldn't Allocate TCP Decoder\n") );
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc = DecodeTCP;
	if (!DecoderAddDecoder(GetDecoderByName("IP"), DecoderID)) {
		PRINTERROR("Failed to Bind TCP Decoder to IPDefrag Decoder\n");
		return FALSE;
	}

	IPDecoderID = GetDecoderByName("IP");

	return TRUE;
}
