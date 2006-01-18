#ifndef HOGWASH_MACFILTER_H
#define HOGWASH_MACFILTER_H

#include "../config.h"
#include "../engine/hogwash.h"
#include "route.h"


/*TODO: make this not so ethernet specific*/

#define MAX_MACS		1024

typedef struct mac_rec{
	unsigned char	MAC[6];
	int				Interface;
	int				Count;
} MacRec;

int InitMacFilter();


#endif