#ifndef _HOGWASH_DECODE_UDP_H_
#define _HOGWASH_DECODE_UDP_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"

typedef struct udp_header {
  unsigned short	source;
  unsigned short	dest;
  unsigned short	len;
  unsigned short	check;
} UDPHdr;


typedef struct udp_data{
	UDPHdr*		Header;
} UDPData;


int InitDecoderUDP();

#endif
