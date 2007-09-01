#include "action_route_sip.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../decoders/decode_ip.h"
#include "../routes/route_sip.h"
#include <stdlib.h>
#include <string.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>

//#define DEBUG

typedef struct action_route_sip{
	int 		Interface;
	int			Timeout;
	int			MaxPerSec;
	NumList*	LocalList;
} ActionRouteSIPRec;

extern GlobalVars	Globals;
int IPDecoderID;

/******************************************
* Parse the args for this action
******************************************/
void* RouteSIPParseArgs(char* Args){
	ActionRouteSIPRec*	data;
	char*				c;
	char*				c2;
	int					i;
	int					InterfaceNum;

	DEBUGPATH;

	/*interface is the first arg*/
	c=strchr(Args, ',');
	if (!c){
		printf("Expected ,\n");
		return NULL;
	}
	
	*c=0x00;
	c++;
	
	for (i=0;i<Globals.NumInterfaces;i++){
		if (strcasecmp(Globals.Interfaces[i].Name, Args)==0){
#ifdef DEBUG
			printf("Interface set to %i(%s)\n",i, Globals.Interfaces[i].Name);
#endif
			InterfaceNum=i;
			break;
		}
	}
	
	if (i==Globals.NumInterfaces){
		printf("Error: \"%s\" is not an interface name\n",Args);
		return NULL;
	}
	
	/*timeout is the second arg*/ 
	data=(ActionRouteSIPRec*)calloc(sizeof(ActionRouteSIPRec),1);
	data->Interface=InterfaceNum;
	data->Timeout=atoi(c);
	data->LocalList=InitNumList(LIST_TYPE_NORMAL);
	data->MaxPerSec=0;
	
#ifdef DEBUG
	printf("Timout set to %i\n",data->Timeout);
#endif	
		
	/*Number of seconds per drop is third*/
	c2=strchr(c+1, ',');
	if (!c2){
		printf("Expected ,\n");
		return NULL;
	}
	
	*c2=0x00;
	c2++;
	
	data->MaxPerSec=atoi(c2);
	
#ifdef DEBUG
	printf("Limiting to %i Reroutes/Sec\n",data->MaxPerSec);
#endif	

	c2=strchr(c2+1, ',');
	if (!c2){
		printf("Expected ,\n");
		return NULL;
	}
	
	*c2=0x00;
	c2++;
	while (*c2==' ') c2++;

	/*Last is a list of non-routable*/
	if (!AddIPRanges(data->LocalList, c2)){
		printf("Couldn't understand local IP's (%s)\n",c2);
		free(data);
		return NULL;
	}
	
	
	return data;
}


/******************************************
* handle informational messages
******************************************/
int RouteSIPMessage(char* Message, void* Data){

  DEBUGPATH;

	return TRUE;
}

/******************************************
* Reroute this IP
******************************************/
int RouteSIPAction(int RuleNum, int PacketSlot, void* Data){
	ActionRouteSIPRec*	data;
	PacketRec*			p;
	IPData*				IP;
	
	DEBUGPATH;

	if (!Data){
#ifdef DEBUG
		printf("I must have somewhere to route to\n");
#endif	
		return FALSE;
	}
		
	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IP)){
		printf("This packet has no IP header\n");
		return FALSE;
	}
	
	p=&Globals.Packets[PacketSlot];
	data=(ActionRouteSIPRec*)Data;

	if (IsInList(data->LocalList, ntohl(IP->Header->saddr))){
#ifdef DEBUG
		printf("This is in the local list\n");
#endif	
		return FALSE;
	}
			
	/*check to see if we're too fast*/
			
			
	return RouteSIPAdd(IP->Header->saddr, data->Interface, Globals.Packets[PacketSlot].tv.tv_sec+data->Timeout);
}

/********************************
* Set up the sip routing stuff
********************************/
int InitActionRouteSIP(){
	int ActionID;

	DEBUGPATH;

	ActionID=CreateAction("route sip");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action route sip\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=RouteSIPAction;
	Globals.ActionItems[ActionID].MessageFunc=RouteSIPMessage;
	Globals.ActionItems[ActionID].ParseArgs=RouteSIPParseArgs;

	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
