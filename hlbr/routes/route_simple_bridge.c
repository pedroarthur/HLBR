#include "route_simple_bridge.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"

int			EthernetDecoderID;

#define DEBUG

extern GlobalVars	Globals;

/*********************************
* Send it out the other interface
**********************************/
int RouteSBridge(int PacketSlot){
	PacketRec*	p;
#ifdef DEBUGPATH
	printf("In RouteSBridge\n");
#endif

	p=&Globals.Packets[PacketSlot];

	p->TargetInterface=!p->InterfaceNum;
	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Specify the interfaces to bridge
* TODO: make this actually work
**********************************/
int RouteSBridgeAddNode(int RouteID, char* Args){
#ifdef DEBUGPATH
	printf("In RouteSBridgeAddNode\n");
#endif

	return TRUE;
}

/*********************************
* Set up everything to do simple bridging
**********************************/
int InitSBridge(){
	int RouteID;
#ifdef DEBUGPATH
	printf("In InitSBridge\n");
#endif	
	
	if ( (RouteID=CreateRoute("SBridge"))==ROUTE_NONE){
		printf("Couldn't create route SBridge\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteSBridge;
	Globals.Routes[RouteID].AddNode=RouteSBridgeAddNode;
	
	return TRUE;
}

