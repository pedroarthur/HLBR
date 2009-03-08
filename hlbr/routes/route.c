#include "route.h"
#include "route_dip.h"
#include "route_sip.h"
#include "route_macfilter.h"
#include "route_simple_bridge.h"
#include "route_broadcast.h"
#include "route_arp.h"
#include "route_interface.h"
#include "route_bns.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

//#define DEBUG

extern GlobalVars Globals;

/***********************************
* Set up all the routing code
***********************************/
int InitRoutes(){
	DEBUGPATH;

  	if (!InitSBridge()) return FALSE;
	if (!InitRouteDIP()) return FALSE;
	if (!InitRouteSIP()) return FALSE;
	if (!InitMacFilter()) return FALSE;
	if (!InitRouteBroadcast()) return FALSE;
	if (!InitRouteARP()) return FALSE;
	if (!InitRouteInterface()) return FALSE;
	if (!InitRouteBNS()) return FALSE;
		
	return TRUE;
}

/******************************************
* Put a new entry into the routing system
******************************************/
int RouteAdd(int RouteID, char* Args){
	DEBUGPATH;

	if (RouteID>=Globals.NumRoutes)
		return FALSE;

	if (!Globals.Routes[RouteID].AddNode)
		return FALSE;
	
	return Globals.Routes[RouteID].AddNode(RouteID, Args);
}

/***********************************
* Given an route's name, return
* its ID
***********************************/
int GetRouteByName(char* Name){
	int	i;

	DEBUGPATH;

	for (i=0;i<Globals.NumRoutes;i++){
		if (strcasecmp(Name, Globals.Routes[i].Name)==0){
			return i;
		}
	}

	return ROUTE_NONE;
}

/********************************
* Create a new route handler
*********************************/
int CreateRoute(char* Name){
	int RouteID;

	DEBUGPATH;

	/*check to see if this name is already used*/
	RouteID=GetRouteByName(Name);
	if (RouteID!=ROUTE_NONE){
		printf("Route %s already exists\n",Name);
		return ROUTE_NONE;
	}

	RouteID=Globals.NumRoutes;
	Globals.NumRoutes++;

	bzero(&Globals.Routes[RouteID], sizeof(RouteRec));
	Globals.Routes[RouteID].ID=RouteID;
	snprintf(Globals.Routes[RouteID].Name, MAX_NAME_LEN, Name);
	
#ifdef DEBUG
	printf("Allocated Route \"%s\" at number %i\n",Name, RouteID);
#endif	
	
	return RouteID;
}

/**********************************************
* Apply routing rules to this packet
* Returns FALSE if you need to drop the packet
**********************************************/
int Route(int PacketSlot){
	int 		i;
	int 		result;

	DEBUGPATH;

	for (i=0;i<Globals.NumRoutes;i++){
		if (Globals.Routes[i].Active)
			if (Globals.Routes[i].RouteFunc) {
				result=Globals.Routes[i].RouteFunc(PacketSlot);

				if (result==ROUTE_RESULT_DROP)
					return FALSE;

				if (result==ROUTE_RESULT_DONE)
					return TRUE;
			}
	}

	return TRUE;
}

