#ifndef _HOGWASH_DECODE_IP_DEFRAG_H_
#define _HOGWASH_DECODE_IP_DEFRAG_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"
#include "decode_ip.h"

#define FRAG_TIMEOUT		10

#define FRAG_FLAG_RESERVED	4
#define FRAG_FLAG_MAY_FRAG	2
#define FRAG_FLAG_MORE		1

typedef struct ip_defrag_data{
	char		IsRebuilt;
} IPDefragData;

int InitDecoderIPDefrag();

#endif
