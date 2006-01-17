/***************************************************
* Sends all packets with a particular DIP out a 
* particular interface
****************************************************/

#include "route_dip.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"
#include "../decoders/decode.h"
#include "../decoders/decode_ip.h"
#include <arpa/inet.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

int			IPDecoderID;
NumList*	DInterfaces[MAX_INTERFACES];

//#define DEBUG

extern GlobalVars	Globals;

/*******************************************
* Given a DIP, send it out the interface
*******************************************/
int RouteDIP(int PacketSlot){
	IPData*			IData;
	PacketRec*		p;
	int				i;

#ifdef DEBUGPATH
	printf("In RouteDIP\n");
#endif

	p=&Globals.Packets[PacketSlot];
	
	if (!GetDataByID(p->PacketSlot, IPDecoderID, (void**)&IData)){
#ifdef DEBUG
		printf("This isn't an ip packet\n");
#endif	
		return ROUTE_RESULT_CONTINUE;
	}

#ifdef DEBUG
	printf("%s->",inet_ntoa(*(struct in_addr*)&IData->Header->saddr));
	printf("%s\n",inet_ntoa(*(struct in_addr*)&IData->Header->daddr));
	printf("This packet is from %i(%s)\n",p->InterfaceNum, Globals.Interfaces[p->InterfaceNum].Name);
#endif

	/*TODO: Make this more efficient*/
	for (i=0;i<Globals.NumInterfaces;i++){
		if (DInterfaces[i]){
			if (IsInList(DInterfaces[i], ntohl(IData->Header->daddr))){
#ifdef DEBUG
				printf("Found a DIP route for this packet.  Going out interface %i(%s)\n",i,Globals.Interfaces[i].Name);
#endif	
				p->TargetInterface=i;
				return ROUTE_RESULT_DONE;		
			}
		}
	}
	
#ifdef DEBUG
	printf("There isn't a route set for this DIP\n");
#endif	
	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Add some members to the dip list
* First arg is the interface
* followed by the dest IP's
**********************************/
int RouteDIPAddNode(int RouteID, char* Args){
	int		i;
	char*	sp;
	int		InterfaceNum;
	
#ifdef DEBUGPATH
	printf("In RouteDIPAddNode\n");
#endif
	
#ifdef DEBUG	
	printf("Adding with args %s\n",Args);
#endif

	/*first pop off the interface*/
	sp=strchr(Args, ' ');
	if (!sp){
		printf("Expected Interface Name\nFormat: DIP(<interface> <dip>,<dip>,.....)\n");
		return FALSE;
	}
	
	*sp=0x00;
	sp++;
	while (*sp==' ') sp++;
	if (sp==0x00){
		printf("Expected Destination IP\nFormat: DIP(<interface> <dip>,<dip>,.....)\n");
		return FALSE;	
	}
	
	/*see if that interface exists*/
#ifdef DEBUG
	printf("Searching for interface \"%s\"\n",Args);
#endif	
	for (i=0;i<Globals.NumInterfaces;i++){
		if (strcasecmp(Args, Globals.Interfaces[i].Name)==0){
			InterfaceNum=i;
			break;
		}
	}

	if (i==Globals.NumInterfaces){
		printf("Unknown Interface \"%s\"\n",Args);
		return FALSE;
	}
	
	if (!DInterfaces[InterfaceNum]){
		DInterfaces[InterfaceNum]=InitNumList(LIST_TYPE_NORMAL);
	}
	
	if (!AddIPRanges(DInterfaces[InterfaceNum], sp)){
		printf("Failed to parse IP list \"%s\"\n",sp);
		return FALSE;
	}
		
	return TRUE;
}

/****************************************
* Set up everything to do dip routing
****************************************/
int InitRouteDIP(){
	int RouteID;
	
#ifdef DEBUGPATH
	printf("In InitRoutDIP\n");
#endif	

	bzero(DInterfaces, sizeof(NumList*) * MAX_INTERFACES);
	
	if ( (RouteID=CreateRoute("DIP"))==ROUTE_NONE){
		printf("Couldn't create route DIP\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteDIP;
	Globals.Routes[RouteID].AddNode=RouteDIPAddNode;
	
	if ( (IPDecoderID=GetDecoderByName("IP"))==DECODER_NONE){
		printf("Couldn't find the IP Deoder\n");
		return FALSE;
	}
	
	return TRUE;
}

