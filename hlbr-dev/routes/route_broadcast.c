/***************************************************
* Sends broadcast packet out all interfaces
****************************************************/

#include "route_broadcast.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"
#include "../decoders/decode.h"
#include "../decoders/decode_ethernet.h"
#include <arpa/inet.h>

int			EthernetDecoderID;

//#define DEBUG
//#define DEBUGPATH

extern GlobalVars	Globals;

/*******************************************
* If this is a broadcast packet, send out all
*******************************************/
int RouteBroadcast(int PacketSlot){
	EthernetData*	EData;
	PacketRec*		p;

#ifdef DEBUGPATH
	printf("In RouteBroadcast\n");
#endif

	p=&Globals.Packets[PacketSlot];
	
	if (!GetDataByID(p->PacketSlot, EthernetDecoderID, (void**)&EData)){
#ifdef DEBUG
		printf("This isn't an ethernet packet\n");
#endif	
		return ROUTE_RESULT_CONTINUE;
	}

#ifdef DEBUG
	printf("Checking Ethernet Broadcast %02X:%02X:%02X:%02X:%02X:%02X->%02X:%02X:%02X:%02X:%02X:%02X\n",
		EData->Header->SrcMac[0],
		EData->Header->SrcMac[1],
		EData->Header->SrcMac[2],
		EData->Header->SrcMac[3],
		EData->Header->SrcMac[4],
		EData->Header->SrcMac[5],
		
		EData->Header->DstMac[0],
		EData->Header->DstMac[1],
		EData->Header->DstMac[2],
		EData->Header->DstMac[3],
		EData->Header->DstMac[4],
		EData->Header->DstMac[5]);
#endif

	if ( 
		(EData->Header->DstMac[0]==0xFF) &&
		(EData->Header->DstMac[1]==0xFF) &&
		(EData->Header->DstMac[2]==0xFF) &&
		(EData->Header->DstMac[3]==0xFF) &&
		(EData->Header->DstMac[4]==0xFF) &&
		(EData->Header->DstMac[5]==0xFF)
	){
#ifdef DEBUG
		printf("This is an ethernet broadcast\n");
#endif	
		p->TargetInterface=INTERFACE_BROADCAST;
		return ROUTE_RESULT_DONE;
	}
	
	
#ifdef DEBUG
	printf("There isn't a route set for this packet\n");
#endif	
	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Turn on routing of broadcast packets
**********************************/
int RouteBroadcastAddNode(int RouteID, char* Args){	
#ifdef DEBUGPATH
	printf("In RouteBroadcastAddNode\n");
#endif
	
#ifdef DEBUG	
	printf("Adding with args %s\n",Args);
#endif

	return TRUE;
}

/****************************************
* Set up everything to handle broadcast packets
****************************************/
int InitRouteBroadcast(){
	int RouteID;
	
#ifdef DEBUGPATH
	printf("In InitRoutBroadcast\n");
#endif	

	if ( (RouteID=CreateRoute("Broadcast"))==ROUTE_NONE){
		printf("Couldn't create route Broadcast\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteBroadcast;
	Globals.Routes[RouteID].AddNode=RouteBroadcastAddNode;
	
	if ( (EthernetDecoderID=GetDecoderByName("Ethernet"))==DECODER_NONE){
		printf("Couldn't find the Ethernet Decoder\n");
		return FALSE;
	}
	
	return TRUE;
}

