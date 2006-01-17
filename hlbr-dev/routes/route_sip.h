#ifndef HOGWASH_SIP_H
#define HOGWASH_SIP_H

#include "../config.h"
#include "../engine/hogwash.h"
#include "route.h"

#define MAX_RSIPS		256

int InitRouteSIP();
int RouteSIPAdd(unsigned int SIP, int Interface, long UntilTime);


#endif
