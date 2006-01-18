#ifndef HLBR_SIP_H
#define HLBR_SIP_H

#include "../config.h"
#include "../engine/hlbr.h"
#include "route.h"

#define MAX_RSIPS		256

int InitRouteSIP();
int RouteSIPAdd(unsigned int SIP, int Interface, long UntilTime);


#endif
