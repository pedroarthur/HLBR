/***************************************************
* On Some OS's you see all the traffic you just
* sent so you need to filter by mac address.
* If you don't you'll pick a packet up off one
* interface, see it on the other and broadcast
* it back on the first in an infinite loop.
*
* TODO: Make MACS time out
* TODO: Finish handling broadcast packets
****************************************************/

#include "route_macfilter.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"
#include "../decoders/decode.h"
#include "../decoders/decode_ethernet.h"
#ifdef _SOLARIS_
#include <strings.h>
#endif

MacRec		Macs[MAX_MACS];
int 		NumMacs;
NumList*	MacFilterInterfaceList;
int			EthernetDecoderID;

//#define DEBUG

extern GlobalVars	Globals;


/*******************************************
* If the mac exists, get it otherwise
* create it
*******************************************/
MacRec* GetMac(unsigned char* Mac, int Create){
	int i;

	DEBUGPATH;

	/*TODO: Make this faster*/
	for (i=0;i<NumMacs;i++){
		if (memcmp(Macs[i].MAC, Mac, 6)==0) return &Macs[i];
	}

	if (Create){
		if (NumMacs==MAX_MACS) return NULL;
#ifdef DEBUG
		printf("New Mac %02X:%02X:%02X:%02X:%02X:%02X\n",Mac[0],Mac[1],Mac[2],Mac[3],Mac[4],Mac[5]);
#endif	
	
		Macs[NumMacs].MAC[0]=Mac[0];
		Macs[NumMacs].MAC[1]=Mac[1];
		Macs[NumMacs].MAC[2]=Mac[2];
		Macs[NumMacs].MAC[3]=Mac[3];
		Macs[NumMacs].MAC[4]=Mac[4];
		Macs[NumMacs].MAC[5]=Mac[5];
		Macs[NumMacs].Count=1;
		Macs[NumMacs].Interface=-1;
	
#ifdef DEBUG
		printf("There are now %i Macs\n",NumMacs+1);
#endif
	
		return &Macs[NumMacs++];
	}
	
	return NULL;
}

/*********************************
* filter duplicates by mac address
**********************************/
int RouteMacFilter(int PacketSlot){
	MacRec*			mac;
	MacRec*			mac2;
	EthernetData*	EData;
	PacketRec*		p;

	DEBUGPATH;
	
	p=&Globals.Packets[PacketSlot];
	
	if (!IsInList(MacFilterInterfaceList, p->InterfaceNum)){
#ifdef DEBUG
		printf("MacFilter doesn't handle this interface\n");
#endif		
		return ROUTE_RESULT_CONTINUE;
	}

	if (!GetDataByID(p->PacketSlot, EthernetDecoderID, (void**)&EData)){
#ifdef DEBUG
		printf("This isn't an ethernet packet\n");
#endif	
		return ROUTE_RESULT_CONTINUE;
	}

#ifdef DEBUG
	printf("%02x:%02x:%02x:%02x:%02x:%02x->",
		EData->Header->SrcMac[0],
		EData->Header->SrcMac[1],
		EData->Header->SrcMac[2],
		EData->Header->SrcMac[3],
		EData->Header->SrcMac[4],
		EData->Header->SrcMac[5]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		EData->Header->DstMac[0],
		EData->Header->DstMac[1],
		EData->Header->DstMac[2],
		EData->Header->DstMac[3],
		EData->Header->DstMac[4],
		EData->Header->DstMac[5]);		
	printf("This packet is from %i(%s)\n",p->InterfaceNum, Globals.Interfaces[p->InterfaceNum].Name);
#endif

	/*check to see if this is an ethernet broadcast*/
	if ( (EData->Header->DstMac[0]==0xFF) &&
		 (EData->Header->DstMac[1]==0xFF) &&
		 (EData->Header->DstMac[2]==0xFF) &&
		 (EData->Header->DstMac[3]==0xFF) &&
		 (EData->Header->DstMac[4]==0xFF) &&
		 (EData->Header->DstMac[5]==0xFF)
	){
#ifdef DEBUG
		printf("This is an ethernet broadcast packet.  Send it to everyone\n");
#endif	
		mac=GetMac(EData->Header->SrcMac, 1);
		mac->Interface=p->InterfaceNum;
		p->TargetInterface=INTERFACE_BROADCAST;
		return ROUTE_RESULT_CONTINUE;
	}

	
	mac=GetMac(EData->Header->SrcMac, 1);
	if (mac->Interface==-1){
		mac->Interface=p->InterfaceNum;
		return ROUTE_RESULT_DROP;
	}
	
	if (mac->Count<50) mac->Count++;
	
	if (mac->Count<3) return ROUTE_RESULT_DROP;
	
	mac2=GetMac(EData->Header->DstMac, 0);
	
	if  (!mac2){
#ifdef DEBUG
		printf("I don't know which interface this goes out.  Broadcast\n");
#endif	
		p->TargetInterface=INTERFACE_BROADCAST;
		return ROUTE_RESULT_CONTINUE;
	}else{
#ifdef DEBUG
		printf("The target is on interface %i(%s)\n",mac2->Interface, Globals.Interfaces[mac2->Interface].Name);
#endif		
		p->TargetInterface=mac2->Interface;
		return ROUTE_RESULT_CONTINUE;
	}
}

/*********************************
* Add some members to the macfilter list
**********************************/
int RouteMacFilterAddNode(int RouteID, char* Args){
	NumAlias*	Aliases;
	int			i;	
	int			Count;
	
	DEBUGPATH;

	DBG( PRINT1("AddNode was called with args %s\n", Args) );

	if (!Args) return FALSE;
	
	Aliases=calloc(sizeof(NumAlias),Globals.NumInterfaces);
	for (i=0;i<Globals.NumInterfaces;i++){
		snprintf(Aliases[i].Alias, 512, Globals.Interfaces[i].Name);
		Aliases[i].Num=Globals.Interfaces[i].ID;
	}
	
	if (!AddRangesString(MacFilterInterfaceList, Args, Aliases, Globals.NumInterfaces)){
		printf("Failed to parse interface list\n");
		free(Aliases);
		return FALSE;
	}

	Count=0;
	for (i=0;i<Globals.NumInterfaces;i++)
		if (IsInList(MacFilterInterfaceList, i)){
#ifdef DEBUG
			printf("Interface %s is handled by macfilter\n",Globals.Interfaces[i].Name);
#endif		
			Count++;	
		}else{
#ifdef DEBUG		
			printf("interface %s is not a macfilter interface\n",Globals.Interfaces[i].Name);
#endif			
		}	
	
	if (Count<2){
		printf("You must specify at least two interfaces to use macfilter\n");
		free(Aliases);
		return FALSE;
	}
	
	free(Aliases);
	return TRUE;
}

/*********************************
* Set up everything to do mac
* matching
**********************************/
int InitMacFilter(){
	int RouteID;

	DEBUGPATH;

	bzero(Macs, sizeof(MacRec) * MAX_MACS);
	
	if ( (RouteID=CreateRoute("MacFilter"))==ROUTE_NONE){
		printf("Couldn't create route MacFilter\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteMacFilter;
	Globals.Routes[RouteID].AddNode=RouteMacFilterAddNode;
	MacFilterInterfaceList=InitNumList(LIST_TYPE_NORMAL);
	
	if ( (EthernetDecoderID=GetDecoderByName("Ethernet"))==DECODER_NONE){
		printf("Couldn't find the Ethernet Deoder\n");
		return FALSE;
	}
	
	return TRUE;
}

