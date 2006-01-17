#ifndef _HOGWASH_DECODE_TCP_STREAM_H_
#define _HOGWASH_DECODE_TCP_STREAM_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"


typedef struct tcp_stream_data{
	unsigned int	SessionID;
	unsigned short	SPort; /*port that started the conversation*/
	unsigned short 	DPort; /*listening port*/
} TCPStreamData;


int InitDecoderTCPStream();

#endif
