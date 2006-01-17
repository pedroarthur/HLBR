#ifndef HOGWASH_DIP_H
#define HOGWASH_DIP_H

#include "../config.h"
#include "../engine/hogwash.h"
#include "route.h"

#define MAX_RDIPS		256

int InitRouteDIP();
int RouteDIPAdd(unsigned int DIP, int Interface);


#endif
