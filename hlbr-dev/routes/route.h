#ifndef HOGWASH_ROUTE_H
#define HOGWASH_ROUTE_H

#include "../config.h"
#include "../engine/hogwash.h"

#define ROUTE_NONE	-1

#define ROUTE_RESULT_DROP		0
#define ROUTE_RESULT_CONTINUE	1
#define ROUTE_RESULT_DONE		2

int InitRoutes();
int CreateRoute(char* Name);
int	GetRouteByName(char* Name);
int RouteAdd(int RouteID, char* Args);
int Route(int PacketSlot);

#endif
