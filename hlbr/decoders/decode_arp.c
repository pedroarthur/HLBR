#include "decode_arp.h"
#include "decode_ethernet.h"
#include "../packets/packet.h"
#include "../engine/hlbr.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#define DEBUG

extern GlobalVars	Globals;

int	EthernetDecoderID;

/**
 * Apply the ARP decoding.
 */
void* DecodeARP(int PacketSlot)
{
	ARPData*	data;
	EthernetData*	edata;
	unsigned short	etype;
	PacketRec*	p;
	
	DEBUGPATH;

	p = &Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, EthernetDecoderID, (void**)&edata)) {
		DBG( PRINTERROR1("Ethernet decoder ID is %i\n", EthernetDecoderID) );
		DBG( PRINTERROR("Failed to get Ethernet header data\n") );
		return NULL;
	}

	etype = ntohs(edata->Header->Type);
	
	if (etype != ETHERNET_TYPE_ARP) {
		DBG( PRINTERROR1("Ethernet doesn't think this is an ARP packet %04x\n",etype) );
		return NULL;
	}
		
	data = MALLOC(sizeof(ARPData));
	data->Header = (ARPHdr*)(p->RawPacket+p->BeginData);
	p->BeginData += sizeof(ARPHdr);

	if (ntohs(data->Header->Operation) == ARP_OP_REQUEST) {
		DBG( PRINTERROR("ARP Request:\n") );
		data->EthernetARPHeader = (ARPEtherIP*)(p->RawPacket+p->BeginData);		
		p->BeginData += sizeof(ARPEtherIP);

		DBG( PRINTERROR6("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->SenderMac[0],
			data->EthernetARPHeader->SenderMac[1],
			data->EthernetARPHeader->SenderMac[2],
			data->EthernetARPHeader->SenderMac[3],
			data->EthernetARPHeader->SenderMac[4],
			data->EthernetARPHeader->SenderMac[5]) );
		DBG( PRINTERROR1("(%s)\nWho has?\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->SenderIP[0])) );
		DBG( PRINTERROR6("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->TargetMac[0],
			data->EthernetARPHeader->TargetMac[1],
			data->EthernetARPHeader->TargetMac[2],
			data->EthernetARPHeader->TargetMac[3],
			data->EthernetARPHeader->TargetMac[4],
			data->EthernetARPHeader->TargetMac[5]) );
		DBG( PRINTERROR1("(%s)\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->TargetIP[0])) );

	} else if (ntohs(data->Header->Operation) == ARP_OP_REPLY) {
		DBG( PRINTERROR("ARP Reply:\n") );
		data->EthernetARPHeader = (ARPEtherIP*)(p->RawPacket+p->BeginData);		
		p->BeginData += sizeof(ARPEtherIP);

		DBG( PRINTERROR6("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->SenderMac[0],
			data->EthernetARPHeader->SenderMac[1],
			data->EthernetARPHeader->SenderMac[2],
			data->EthernetARPHeader->SenderMac[3],
			data->EthernetARPHeader->SenderMac[4],
			data->EthernetARPHeader->SenderMac[5]) );
		DBG( PRINTERROR1("(%s)\nis at?\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->SenderIP[0])) );
		DBG( PRINTERROR6("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->TargetMac[0],
			data->EthernetARPHeader->TargetMac[1],
			data->EthernetARPHeader->TargetMac[2],
			data->EthernetARPHeader->TargetMac[3],
			data->EthernetARPHeader->TargetMac[4],
			data->EthernetARPHeader->TargetMac[5]) );
		DBG( PRINTERROR1("(%s)\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->TargetIP[0])) );

	} else {
		PRINTERROR1("Unknown ARP Operation %04x\n", ntohs(data->Header->Operation));
	}

	return data;
}


/**
 * Set up the ARP decoder.
 */
int InitDecoderARP()
{
	int DecoderID;

	DEBUGPATH;
	
	if ((DecoderID = CreateDecoder("ARP")) == DECODER_NONE) {
		PRINTERROR("Couldn't Allocate ARP Decoder\n");
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc = DecodeARP;
	if (!DecoderAddDecoder(GetDecoderByName("Ethernet"), DecoderID)) {
		PRINTERROR("Failed to Bind ARP Decoder to Ethernet Decoder\n");
		return FALSE;
	}

	EthernetDecoderID = GetDecoderByName("Ethernet");

	/* for testing */
	Globals.Decoders[DecoderID].Active = TRUE;
	/* end testing */

	return TRUE;
}
