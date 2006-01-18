#ifndef _HLBR_DECODE_TCP_H_
#define _HLBR_DECODE_TCP_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "decode.h"


typedef struct tcp_header {
	unsigned short	source;
	unsigned short	dest;
	unsigned int	seq;
	unsigned int	ack_seq;
#ifdef HLBR_LITTLE_ENDIAN
	unsigned short	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#else
	unsigned short	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#endif	
	unsigned short	window;
	unsigned short	check;
	unsigned short	urg_ptr;
} TCPHdr;



typedef struct tcp_data{
	TCPHdr*			Header;
	unsigned char*	Data;
	unsigned int	DataLen;
} TCPData;


int InitDecoderTCP();

#endif
