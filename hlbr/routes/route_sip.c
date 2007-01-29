/***************************************************
* Sends all packets with a particular SIP out a 
* particular interface
****************************************************/

#include "route_sip.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"
#include "../decoders/decode.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_arp.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../routes/route_sip.h"
#ifdef _SOLARIS_
#include <strings.h>
#endif

int			IPDecoderID;
int			ARPDecoderID;
NumList*	SInterfaces[MAX_INTERFACES];

//#define DEBUG

extern GlobalVars	Globals;

/*******************************************
* Given a SIP, send it out the interface
*******************************************/
int RouteSIP(int PacketSlot){
	ARPData*		AData;
	IPData*			IData;
	PacketRec*		p;
	int				i;
	int				Timeout;
	unsigned int	IP;

#ifdef DEBUGPATH
	printf("In RouteSIP\n");
#endif

	p=&Globals.Packets[PacketSlot];
	
	if (GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
#ifdef DEBUG
		printf("%s->",inet_ntoa(*(struct in_addr*)&IData->Header->saddr));
		printf("%s\n",inet_ntoa(*(struct in_addr*)&IData->Header->daddr));
		printf("This packet is from %i(%s)\n",p->InterfaceNum, Globals.Interfaces[p->InterfaceNum].Name);
#endif
		IP=ntohl(IData->Header->saddr);
	}else if (GetDataByID(PacketSlot, ARPDecoderID, (void**)&AData)){
		if (AData->Header->Operation!=ARP_OP_REPLY){
#ifdef DEBUG
			printf("Wasn't an arp reply\n");
#endif		
			return ROUTE_RESULT_CONTINUE;
		}
		
		IP=ntohl(*(unsigned int*)&AData->EthernetARPHeader->SenderIP[0]);
#ifdef DEBUG
		printf("Arp Reply from %s\n",inet_ntoa(*(struct in_addr*)&IP));
#endif		
	}else{
#ifdef DEBUG
		printf("This isn't an ip packet or an arp packet\n");
#endif		
		return ROUTE_RESULT_CONTINUE;
	}


	/*TODO: Make this more efficient*/
/*replacing logic with a time list*/
/*
	for (i=0;i<Globals.NumInterfaces;i++){
		if (SInterfaces[i]){
			if (IsInListUser(SInterfaces[i], IP,(void**)&Timeout )){
				if (Timeout!=0 && Timeout<Globals.Packets[PacketSlot].tv.tv_sec){
#ifdef DEBUG
					printf("This route has expired\n");
#endif				
					RemoveFromList(SInterfaces[i], ntohl(IData->Header->saddr));
					return ROUTE_RESULT_CONTINUE;
				}else{
#ifdef DEBUG
					printf("Found a SIP route for this packet.  Going out interface %i(%s)\n",i,Globals.Interfaces[i].Name);
#endif	
					p->TargetInterface=i;
					return ROUTE_RESULT_DONE;
				}
			}
		}
	}
*/	

#ifdef DEBUG
	printf("There isn't a route set for this SIP\n");
#endif	
	return ROUTE_RESULT_CONTINUE;
}

/*********************************
* Add some members to the sip list
* First arg is the interface
* followed by the dest IP's
**********************************/
int RouteSIPAddNode(int RouteID, char* Args){
	int		i;
	char*	sp;
	int		InterfaceNum;
	
#ifdef DEBUGPATH
	printf("In RouteSIPAddNode\n");
#endif
	
#ifdef DEBUG	
	printf("Adding with args %s\n",Args);
#endif

	/*first pop off the interface*/
	sp=strchr(Args, ' ');
	if (!sp){
		printf("Expected Interface Name\nFormat: SIP(<interface> <sip>,<sip>,.....)\n");
		return FALSE;
	}
	
	*sp=0x00;
	sp++;
	while (*sp==' ') sp++;
	if (sp==0x00){
		printf("Expected Destination IP\nFormat: SIP(<interface> <sip>,<sip>,.....)\n");
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
	
	if (!SInterfaces[InterfaceNum]){
		SInterfaces[InterfaceNum]=InitNumList(LIST_TYPE_NORMAL);
	}
	
	if (!AddIPRanges(SInterfaces[InterfaceNum], sp)){
		printf("Failed to parse IP list \"%s\"\n",sp);
		return FALSE;
	}
		
	return TRUE;
}

/****************************************
* Set up everything to do sip routing
****************************************/
int InitRouteSIP(){
	int RouteID;
	
#ifdef DEBUGPATH
	printf("In InitRoutSIP\n");
#endif	

	bzero(SInterfaces, sizeof(NumList*) * MAX_INTERFACES);
	
	if ( (RouteID=CreateRoute("SIP"))==ROUTE_NONE){
		printf("Couldn't create route SIP\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteSIP;
	Globals.Routes[RouteID].AddNode=RouteSIPAddNode;
	
	if ( (IPDecoderID=GetDecoderByName("IP"))==DECODER_NONE){
		printf("Couldn't find the IP Deoder\n");
		return FALSE;
	}

	if ( (ARPDecoderID=GetDecoderByName("ARP"))==DECODER_NONE){
		printf("Couldn't find the ARP Deoder\n");
		return FALSE;
	}
	
	return TRUE;
}

/************************************************
* Add a temporary/permanent SIP route
*************************************************/
int RouteSIPAdd(unsigned int SIP, int Interface, long UntilTime){
#ifdef DEBUGPATH
	printf("In RouteSIPAdd\n");
#endif
	
#ifdef DEBUG
	printf("Rerouting %s\n", inet_ntoa(*(struct in_addr*)&SIP));
#endif	
	
	if (!SInterfaces[Interface]){
		SInterfaces[Interface]=InitNumList(LIST_TYPE_NORMAL);
#ifdef DEBUG		
		printf("This is the first for this interface\n");
#endif		
		return FALSE;
	}
	
	if (IsInList(SInterfaces[Interface], htonl(SIP))){
#ifdef DEBUG
		printf("This IP was already rerouted\n");
#endif	
		return TRUE;
	}
	
/*replacing with a time list*/
/*	if (!AddRangeUser(SInterfaces[Interface], htonl(SIP), htonl(SIP), (void*)UntilTime)){
		printf("Couldn't add route\n");
		return FALSE;
	}
*/
	/*mark route_sip as active in case it's not*/
	Globals.Routes[GetRouteByName("SIP")].Active=TRUE;

	return TRUE;
}
