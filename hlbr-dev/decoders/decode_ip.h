#ifndef _HOGWASH_DECODE_IP_H_
#define _HOGWASH_DECODE_IP_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"

#define IP_PROTO_ICMP	1
#define IP_PROTO_TCP	6
#define IP_PROTO_UDP	17

typedef struct ip_header{
#ifdef HOGWASH_LITTLE_ENDIAN
	unsigned char	ihl:4,
		version:4;
#else
	unsigned char	version:4,
  		ihl:4;
#endif		
	unsigned char	tos;
	unsigned short	tot_len;
	unsigned short	id;
	unsigned short	frag_off;
	unsigned char	ttl;
	unsigned char	protocol;
	unsigned short	check;
	unsigned int	saddr;
	unsigned int	daddr;
	/*The options start here. */
} IPHdr;

typedef struct ip_data{
	IPHdr*		Header;
} IPData;


int InitDecoderIP();

#endif
