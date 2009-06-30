#include "route_simple_bridge.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"

/* #define DEBUG */

#define SBMask	0xFF000000

extern GlobalVars	Globals;

int 			SBridgeID;

/*********************************
* Send it out the other interface
**********************************/
int RouteSBridge(int PacketSlot){
	PacketRec*	p;

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	if (Globals.Interfaces[p->InterfaceNum].RouteID == SBridgeID) {
		p->TargetInterface = (int) Globals.Interfaces[p->InterfaceNum].RouteData;
		return ROUTE_RESULT_DONE;
	}

	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Specify the interfaces to bridge
**********************************/
int RouteSBridgeAddNode(int RouteID, char* Args){
	int InterfaceA;
	int InterfaceB;

	DEBUGPATH;

#ifdef DEBUG
	printf ("Adding a SBridge node with \"%s\" as Args\n", Args);
#endif

	InterfaceA = GetInterfaceByName(strtok(Args, ", "));
	InterfaceB = GetInterfaceByName(strtok(NULL, ", "));

	if (InterfaceA == INTERFACE_NONE) {
		fprintf (stderr, "%s: Couldn't parse arguments %s\n", __FUNCTION__, Args);
		return FALSE;
	}

	if (InterfaceB == INTERFACE_NONE) {
		fprintf (stderr, "%s: Couldn't parse arguments %s\n", __FUNCTION__, Args);
		return FALSE;
	}

	if (Globals.Interfaces[InterfaceA].RouteID != ROUTE_NONE) {
		fprintf (stderr, "%s: Interface %s already routed\n",
			 __FUNCTION__, Globals.Interfaces[InterfaceA].Name);

		return FALSE;
	}

	if (Globals.Interfaces[InterfaceB].RouteID != ROUTE_NONE) {
		fprintf (stderr, "%s: Interface %s already routed\n",
			 __FUNCTION__, Globals.Interfaces[InterfaceB].Name);

		return FALSE;
	}

	Globals.Interfaces[InterfaceA].RouteData = (void *) InterfaceB;
	Globals.Interfaces[InterfaceB].RouteData = (void *) InterfaceA;

	Globals.Interfaces[InterfaceB].RouteID = SBridgeID;

	return TRUE;
}

/*********************************
* Set up everything to do simple bridging
**********************************/
int InitSBridge(){
	DEBUGPATH;
	
	if ((SBridgeID=CreateRoute("SBridge"))==ROUTE_NONE){
		printf("Couldn't create route SBridge\n");
		return FALSE;
	}
	
	Globals.Routes[SBridgeID].RouteFunc=RouteSBridge;
	Globals.Routes[SBridgeID].AddNode=RouteSBridgeAddNode;
	
	return TRUE;
}

#ifdef DEBUG
#undef DEBUG
#endif
