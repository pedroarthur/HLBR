#ifndef HLBR_DIP_H
#define HLBR_DIP_H

#include "../config.h"
#include "../engine/hlbr.h"
#include "route.h"

#define MAX_RDIPS		256

int InitRouteDIP();
int RouteDIPAdd(unsigned int DIP, int Interface);


#endif
