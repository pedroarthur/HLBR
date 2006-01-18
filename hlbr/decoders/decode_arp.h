#ifndef _HLBR_DECODE_ARP_H_
#define _HLBR_DECODE_ARP_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "decode.h"

#define ARP_TYPE_ETHERNET	0x0001
#define ARP_TYPE_IP			0x0800

#define ARP_OP_REQUEST		0x0001
#define ARP_OP_REPLY		0x0002

typedef struct arp_header{
	unsigned short		HardwareType;
	unsigned short		ProtocolType;
	unsigned char		HardwareLen;
	unsigned char		ProtocolLen;
	unsigned short		Operation;
} ARPHdr;

typedef struct arp_ether_ip{
	unsigned char		SenderMac[6];
	unsigned char		SenderIP[4];  /*leave as char so they're packed propertly*/
	unsigned char		TargetMac[6];
	unsigned char		TargetIP[4];
} ARPEtherIP;

typedef struct arp_data{
	ARPHdr*		Header;
	ARPEtherIP*	EthernetARPHeader;
} ARPData;


int InitDecoderARP();

#endif
