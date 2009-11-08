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
#include "../engine/hlbrlib.h"
#ifdef _SOLARIS_
#include <strings.h>
#endif

// MacRec		Macs[MAX_MACS];
// int 		NumMacs;
// NumList*	MacFilterInterfaceList;
int		EthernetDecoderID;

int		MacFilterRouteID;

//#define DEBUG

extern GlobalVars	Globals;


/*******************************************
* If the mac exists, get it otherwise
* create it
*******************************************/
MacRec* GetMac(MacFilterNode *node, unsigned char* Mac, int Create){
	int i;

	DEBUGPATH;

	/*TODO: Make this faster*/
	for (i = 0 ; i < node->NumMacs ; i++){
		if (memcmp(node->Macs[i].MAC, Mac, 6)==0)
			return &node->Macs[i];
	}

	if (Create){
		if (node->NumMacs==MAX_MACS)
			return NULL;
#ifdef DEBUG
		printf("New Mac %02X:%02X:%02X:%02X:%02X:%02X\n",Mac[0],Mac[1],Mac[2],Mac[3],Mac[4],Mac[5]);
#endif	
	
		node->Macs[node->NumMacs].MAC[0]=Mac[0];
		node->Macs[node->NumMacs].MAC[1]=Mac[1];
		node->Macs[node->NumMacs].MAC[2]=Mac[2];
		node->Macs[node->NumMacs].MAC[3]=Mac[3];
		node->Macs[node->NumMacs].MAC[4]=Mac[4];
		node->Macs[node->NumMacs].MAC[5]=Mac[5];
		node->Macs[node->NumMacs].Count=1;
		node->Macs[node->NumMacs].Interface=-1;
	
#ifdef DEBUG
		printf("There are now %i Macs\n",node->NumMacs+1);
#endif
	
		return &node->Macs[node->NumMacs++];
	}
	
	return NULL;
}

/*********************************
* filter duplicates by mac address
**********************************/
int RouteMacFilter(int PacketSlot){
	MacRec			*mac;
	MacRec			*mac2;

	EthernetData		*EData;
	PacketRec		*p;

	MacFilterNode		*node;

	DEBUGPATH;
	
	p=&Globals.Packets[PacketSlot];
	
	if (Globals.Interfaces[p->InterfaceNum].RouteID != MacFilterRouteID){
#ifdef DEBUG
		printf("MacFilter doesn't handle this interface\n");
#endif		
		return ROUTE_RESULT_CONTINUE;
	}

	node = (MacFilterNode *) Globals.Interfaces[p->InterfaceNum].RouteData;

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
	if (!memcmp(EData->Header->DstMac, "\377\377\377\377\377\377", 6)){
#ifdef DEBUG
		printf("This is an ethernet broadcast packet.  Send it to everyone\n");
#endif	
		mac=GetMac(node, EData->Header->SrcMac, 1);
		mac->Interface=p->InterfaceNum;

		p->TargetInterface=INTERFACE_BROADCAST;

		return ROUTE_RESULT_CONTINUE;
	}

	
	mac=GetMac(node, EData->Header->SrcMac, 1);

	if (mac->Interface==-1){
		mac->Interface=p->InterfaceNum;
		return ROUTE_RESULT_DROP;
	}

	if (mac->Count<50)
		mac->Count++;

	if (mac->Count<3)
		return ROUTE_RESULT_DROP;
	
	mac2=GetMac(node, EData->Header->DstMac, 0);
	
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
	Stack *astack = StackNew();
	char *aux;
	int i;

	MacFilterNode* node;

	InterfaceRec *iface;

	#ifdef DEBUG
	printf ("%s was called with args %s\n", __FUNCTION__, Args);
	#endif

	if (!Args)
		return FALSE;

	aux = strtok (Args, ", ");

	do {
		int IfaceID = GetInterfaceByName(aux);

		if (IfaceID == INTERFACE_NONE) {
			fprintf (stderr, "%s: No such a interface %s\n", __FUNCTION__, aux);
			StackDestroy(astack);
			return FALSE;
		}

		StackPushData(astack, (void *) IfaceID);

		aux = strtok (NULL, ", ");
	} while (aux != NULL);

	if (StackGetSize(astack) < 2) {
		fprintf (stderr, "%s: Need two or more interfaces\n", __FUNCTION__);
		StackDestroy(astack);

		return FALSE;
	}

	node = (MacFilterNode *) malloc (sizeof(MacFilterNode));

	node->IfaceArray = (int *) malloc (StackGetSize(astack) * sizeof(int));
	node->IfacesCount = StackGetSize(astack);

	for (i = 0 ; i < node->IfacesCount ; i++) {
		node->IfaceArray[i] = (int) StackPopData (astack);

		iface = &Globals.Interfaces[node->IfaceArray[i]];

		if (iface->RouteID != ROUTE_NONE) {
			fprintf(stderr, "%s: Interface %s route already setted\n", __FUNCTION__, iface->Name);

			StackDestroy(astack);
			free(node->IfaceArray);
			free(node);

			return FALSE;
		}

		iface->RouteID = MacFilterRouteID;
		iface->RouteData = (void *)node;
	}

	bzero (node->Macs, sizeof(MacRec) * MAX_MACS);
	node->NumMacs = 0;

	StackDestroy(astack);

	return TRUE;
}

/*********************************
* Set up everything to do mac
* matching
**********************************/
int InitMacFilter(){
	DEBUGPATH;

	MacFilterRouteID = CreateRoute("MacFilter");

	if (MacFilterRouteID == ROUTE_NONE){
		printf("Couldn't create route MacFilter\n");
		return FALSE;
	}

	Globals.Routes[MacFilterRouteID].RouteFunc = RouteMacFilter;
	Globals.Routes[MacFilterRouteID].AddNode = RouteMacFilterAddNode;

	EthernetDecoderID = GetDecoderByName("Ethernet");

	if (EthernetDecoderID == DECODER_NONE){
		printf("Couldn't find the Ethernet Deoder\n");
		return FALSE;
	}

	return TRUE;
}

