#ifndef _HLBR_DECODE_INTERFACE_H_
#define _HLBR_DECODE_INTERFACE_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "decode.h"


typedef struct interface_data{
	InterfaceRec*	r;
} InterfaceData;

int InitDecoderInterface();

#endif
