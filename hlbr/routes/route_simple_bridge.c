#include "route_simple_bridge.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"

/* #define DEBUG */

#define SBMask	0xFF000000

extern GlobalVars	Globals;

/*********************************
* Send it out the other interface
**********************************/
int RouteSBridge(int PacketSlot){
	PacketRec*	p;

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	if (Globals.Interfaces[p->InterfaceNum].SBData) {
		p->TargetInterface = Globals.Interfaces[p->InterfaceNum].SBData & (~SBMask);
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

	if (Globals.Interfaces[InterfaceA].SBData) {
		fprintf (stderr, "%s: Interface %s already in a Simple Bridge",
			 __FUNCTION__, Globals.Interfaces[InterfaceA].Name);

		return FALSE;
	}

	if (Globals.Interfaces[InterfaceB].SBData) {
		fprintf (stderr, "%s: Interface %s already in a Simple Bridge",
			 __FUNCTION__, Globals.Interfaces[InterfaceB].Name);

		return FALSE;
	}

	Globals.Interfaces[InterfaceA].SBData = SBMask | InterfaceB;
	Globals.Interfaces[InterfaceB].SBData = SBMask | InterfaceA;

	return TRUE;
}

/*********************************
* Set up everything to do simple bridging
**********************************/
int InitSBridge(){
	int RouteID;

	DEBUGPATH;
	
	if ((RouteID=CreateRoute("SBridge"))==ROUTE_NONE){
		printf("Couldn't create route SBridge\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteSBridge;
	Globals.Routes[RouteID].AddNode=RouteSBridgeAddNode;
	
	return TRUE;
}

#ifdef DEBUG
#undef DEBUG
#endif
