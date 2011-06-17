#ifndef _HLBR_DECODE_IP_DEFRAGER_H_
#define _HLBR_DECODE_IP_DEFRAGER_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "decode.h"
#include "decode_ip.h"

#define FRAGMENT_GRACE_TIME 5

#define FRAG_FLAG_RESERVED	4
#define FRAG_FLAG_MAY_FRAG	2
#define FRAG_FLAG_MORE		1

typedef struct ip_defrag_data{
	char		IsRebuilt;
} IPDefragerData;


#endif
