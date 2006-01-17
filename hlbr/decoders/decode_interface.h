#ifndef _HOGWASH_DECODE_INTERFACE_H_
#define _HOGWASH_DECODE_INTERFACE_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"


typedef struct interface_data{
	InterfaceRec*	r;
} InterfaceData;

int InitDecoderInterface();

#endif
