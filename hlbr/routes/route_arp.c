#include "route_arp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"
#include "../decoders/decode_arp.h"
#include <arpa/inet.h>
#include <netinet/in.h>

int			ARPDecoderID;

//#define DEBUG

extern GlobalVars	Globals;

/*********************************
* Explicitly handle arp requests
**********************************/
int RouteARP(int PacketSlot){
	PacketRec*	p;
	ARPData*	Arp;
	
	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, ARPDecoderID, (void**)&Arp)){
#ifdef DEBUG
		printf("This isn't an ARP packet\n");
#endif		
		return ROUTE_RESULT_CONTINUE;
	}
	
#ifdef DEBUG
	printf("Routing an ARP packet\n");
#endif

	if ( 
		(ntohs(Arp->Header->Operation)==ARP_OP_REQUEST) ||
		(ntohs(Arp->Header->Operation)==ARP_OP_REPLY)
	){
		/*send arp requests and arp replies out the broadcast*/
#ifdef DEBUG
		printf("ARP:Setting packet to broacast\n");
#endif
		Globals.Packets[PacketSlot].TargetInterface=INTERFACE_BROADCAST;
		return ROUTE_RESULT_DONE;
	}

#ifdef DEBUG
	printf("Wasn't a known ARP type %04X\n",ntohs(Arp->Header->Operation));
#endif

	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Turn on explicit ARP handling
**********************************/
int RouteARPAddNode(int RouteID, char* Args){
  DEBUGPATH;

	return TRUE;
}

/*********************************
* Set up everything to do
* explict ARP handling
**********************************/
int InitRouteARP(){
	int RouteID;

	DEBUGPATH;
	
	if ( (RouteID=CreateRoute("ARP"))==ROUTE_NONE){
		printf("Couldn't create route ARP\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteARP;
	Globals.Routes[RouteID].AddNode=RouteARPAddNode;
	
	return TRUE;
}

