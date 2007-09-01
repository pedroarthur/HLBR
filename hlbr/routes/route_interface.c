#include "route_interface.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//#define DEBUG

extern GlobalVars	Globals;

/*********************************
* Route based on interface IDs
**********************************/
int RouteInterface(int PacketSlot){
	PacketRec*	p;
	
	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	
	/*testing*/
	if (p->InterfaceNum==2) p->TargetInterface=0;
	/*end testing*/

	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Turn on Interface Routing
**********************************/
int RouteInterfaceAddNode(int RouteID, char* Args){
  DEBUGPATH;

	return TRUE;
}

/*********************************
* Set up interface routing
**********************************/
int InitRouteInterface(){
	int RouteID;
	DEBUGPATH;
	
	if ( (RouteID=CreateRoute("Interface"))==ROUTE_NONE){
		printf("Couldn't create route Interface\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteInterface;
	Globals.Routes[RouteID].AddNode=RouteInterfaceAddNode;
	
	return TRUE;
}

