//#define DEBUG
#include "decode_arp.h"
#include "decode_ethernet.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>


extern GlobalVars	Globals;

int	EthernetDecoderID;

/**
 * Apply the arp decoding.
 */
void* DecodeARP(int PacketSlot){
	ARPData*		data;
	EthernetData*	edata;
	unsigned short	etype;
	PacketRec*		p;
	
	DEBUGPATH;

	p = &Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, EthernetDecoderID, (void**)&edata)){
		fprintf(stderr, "Ethernet decoder ID is %i\n",EthernetDecoderID);
		fprintf(std, "Failed to get Ethernet header data\n");
		return NULL;
	}

	etype = ntohs(edata->Header->Type);
	
	if (etype != ETHERNET_TYPE_ARP) {
#ifdef DEBUG
		printf("Ethernet doesn't think this is an ARP packet %04x\n",etype);
#endif		
		return NULL;
	}
		
	data=malloc(sizeof(ARPData));
	data->Header=(ARPHdr*)(p->RawPacket+p->BeginData);
	p->BeginData+=sizeof(ARPHdr);

	if (ntohs(data->Header->Operation)==ARP_OP_REQUEST){
#ifdef DEBUG	
		printf("ARP Request:\n");		
#endif		
		data->EthernetARPHeader=(ARPEtherIP*)(p->RawPacket+p->BeginData);		
		p->BeginData+=sizeof(ARPEtherIP);

#ifdef DEBUG		
		printf("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->SenderMac[0],
			data->EthernetARPHeader->SenderMac[1],
			data->EthernetARPHeader->SenderMac[2],
			data->EthernetARPHeader->SenderMac[3],
			data->EthernetARPHeader->SenderMac[4],
			data->EthernetARPHeader->SenderMac[5]);
		printf("(%s)\nWho has?\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->SenderIP[0]));
		printf("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->TargetMac[0],
			data->EthernetARPHeader->TargetMac[1],
			data->EthernetARPHeader->TargetMac[2],
			data->EthernetARPHeader->TargetMac[3],
			data->EthernetARPHeader->TargetMac[4],
			data->EthernetARPHeader->TargetMac[5]);
		printf("(%s)\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->TargetIP[0]));
#endif
	} else if (ntohs(data->Header->Operation)==ARP_OP_REPLY){
#ifdef DEBUG	
		printf("ARP Reply:\n");		
#endif		
		data->EthernetARPHeader=(ARPEtherIP*)(p->RawPacket+p->BeginData);		
		p->BeginData+=sizeof(ARPEtherIP);

#ifdef DEBUG		
		printf("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->SenderMac[0],
			data->EthernetARPHeader->SenderMac[1],
			data->EthernetARPHeader->SenderMac[2],
			data->EthernetARPHeader->SenderMac[3],
			data->EthernetARPHeader->SenderMac[4],
			data->EthernetARPHeader->SenderMac[5]);
		printf("(%s)\nis at?\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->SenderIP[0]));
		printf("%02X:%02X:%02X:%02X:%02X:%02X",
			data->EthernetARPHeader->TargetMac[0],
			data->EthernetARPHeader->TargetMac[1],
			data->EthernetARPHeader->TargetMac[2],
			data->EthernetARPHeader->TargetMac[3],
			data->EthernetARPHeader->TargetMac[4],
			data->EthernetARPHeader->TargetMac[5]);
		printf("(%s)\n",inet_ntoa(*(struct in_addr*)&data->EthernetARPHeader->TargetIP[0]));
#endif
	} else {
		printf("Unknown ARP Operation %04x\n", ntohs(data->Header->Operation));
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
#ifdef DEBUG
		printf("Couldn't Allocate ARP Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeARP;
	Globals.Decoders[DecoderID].Free=free;
	if (!DecoderAddDecoder(GetDecoderByName("Ethernet"), DecoderID)){
		fprintf(stderr, "Failed to Bind ARP Decoder to Ethernet Decoder\n");
		return FALSE;
	}

	EthernetDecoderID=GetDecoderByName("Ethernet");

	/* for testing */
	Globals.Decoders[DecoderID].Active = TRUE;
	/* end testing */

	return TRUE;
}


#ifdef DEBUG
#undef DEBUG
#endif
