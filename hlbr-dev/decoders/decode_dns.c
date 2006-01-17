#include "decode_dns.h"
#include "decode_udp.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//#define DEBUG

extern GlobalVars	Globals;

int	UDPDecoderID;

/*********************************************
* Convert raw DNS data to human readable data
**********************************************/
int DNS2Human(char* DNS, char* Human, int HumanLen){
	int		i;
#ifdef DEBUGPATH
	printf("In DNS2Human\n");
#endif	

	i=1;
	while (DNS[i] != 0x00){
		if (i >= HumanLen) return FALSE;
		switch (DNS[i]){
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			Human[i-1]='.';
			break;
		default:
			Human[i-1]=DNS[i];
		}
		i++;
	}
	
	Human[i-1]=0x00;
	
	return TRUE;
}

/***************************************
* Apply the dns decoding
* until I figure out a better way, dns
* only lives on UDP port 53
* TODO: Generate a log if the query is too long
****************************************/
void* DecodeDNS(int PacketSlot){
	DNSData*		data;
	UDPData*		udp_data;
	PacketRec*		p;
	int				i;
	unsigned short	Flags;
	
#ifdef DEBUGPATH
	printf("In DecodeDNS\n");
#endif

#ifdef DEBUG
	printf("Decoding DNS Header\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, UDPDecoderID, (void**)&udp_data)){
		printf("Failed to get UDP header data\n");
		return NULL;
	}
	
	if ( (ntohs(udp_data->Header->dest)==53) || (ntohs(udp_data->Header->source)==53)){
#ifdef DEBUG
		printf("It's on UDP 53, assume it's DNS\n");
#endif	
	}else{
#ifdef DEBUG
		printf("It's not on UDP 53, bail.\n");
#endif		
		return NULL;
	}	
		
	data=malloc(sizeof(DNSData));
	data->Header1=(DNSHeader1*)(p->RawPacket+p->BeginData);
	if (ntohs(data->Header1->Questions)>MAX_DNS_QUESTIONS){
#ifdef DEBUG
		/*TODO: make this an actual alert*/
		printf("Unusual number of questions. Not DNS?\n");
#endif	
		return NULL;
	}
	p->BeginData+=sizeof(DNSHeader1);
	
	
	Flags=ntohs(data->Header1->Flags);
	if (Flags & DNS_FLAG_QUERY){
#ifdef DEBUG	 
		printf("This is a query reply\n");
#endif		
	}else{
#ifdef DEBUG	
		printf("This is a query\n");
#endif		
		/*pull out the questions*/
		for (i=0;i<ntohs(data->Header1->Questions);i++){
			DNS2Human((char*)(p->RawPacket+p->BeginData), data->Q[i].Query, MAX_DNS_QUERY_LEN);
			//data->Q[i].Query=(unsigned char*)(p->RawPacket+p->BeginData);
#ifdef DEBUG
			printf("Query %i is %s\n",i, data->Q[i].Query);
#endif		
		}	 
	}
		
	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderDNS(){
	int DecoderID;

#ifdef DEBUGPATH
	printf("In InitDecoderDNS\n");
#endif
	
	if ((DecoderID=CreateDecoder("DNS"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate DNS Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeDNS;
	if (!DecoderAddDecoder(GetDecoderByName("UDP"), DecoderID)){
		printf("Failed to Bind DNS Decoder to UDP Decoder\n");
		return FALSE;
	}

	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
