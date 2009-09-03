#ifndef HLBR_MACFILTER_H
#define HLBR_MACFILTER_H

#include "../config.h"
#include "../engine/hlbr.h"
#include "route.h"


/*TODO: make this not so ethernet specific*/

#define MAX_MACS		1024

typedef struct mac_rec{
	unsigned char	MAC[6];
	int				Interface;
	int				Count;
} MacRec;

typedef struct macfilternode {
	int *IfaceArray;
	int IfacesCount;
	
	MacRec Macs[MAX_MACS];
	int NumMacs;
} MacFilterNode;

int InitMacFilter();


#endif
