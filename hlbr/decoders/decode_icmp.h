#ifndef _HLBR_DECODE_ICMP_H_
#define _HLBR_DECODE_ICMP_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "decode.h"

#define ICMP_TYPE_ECHOREPLY		0
#define ICMP_TYPE_ECHO			8

typedef struct icmp_header {
  unsigned char		type;
  unsigned char		code;
  unsigned char		checksum;
  union {
	struct {
		unsigned short	id;
		unsigned short	sequence;
	} echo;
	unsigned int	gateway;
	struct {
		unsigned short	__unused;
		unsigned short	mtu;
	} frag;
  } un;
} ICMPHdr;



typedef struct icmp_data{
	ICMPHdr*		Header;
} ICMPData;


int InitDecoderICMP();

#endif
