#ifndef _HOGWASH_DECODE_ETHERNET_H_
#define _HOGWASH_DECODE_ETHERNET_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"

#define ETHERNET_TYPE_IP	0x0800
#define ETHERNET_TYPE_ARP	0x0806

typedef struct ethernet_header{
	unsigned char	DstMac[6];
	unsigned char	SrcMac[6];
	unsigned short	Type;
} EtherHdr;

typedef struct ethernet_data{
	EtherHdr*		Header;
} EthernetData;


int InitDecoderEthernet();

#endif
