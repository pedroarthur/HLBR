#include "action_bns.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../decoders/decode_ip.h"
#include "../routes/route_bns.h"
#include "../actions/action.h"
#include <stdlib.h>
#include <string.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>

//#define DEBUG

typedef struct action_bns{
	NumList*	GreenList;
	int			TimeOut;
} ActionBNSRec;

extern GlobalVars	Globals;
int IPDecoderID;

/******************************************
* Parse the args for this action
******************************************/
void* BNSParseArgs(char* Args){
	ActionBNSRec*		data;
	char*				c;
	char*				c2;

#ifdef DEBUGPATH
	printf("In BNSParseArgs\n");
#endif

#ifdef DEBUG
	printf("Parsing args for action_bns\n");
#endif	

	data=(ActionBNSRec*)calloc(sizeof(ActionBNSRec),1);
	data->GreenList=InitNumList(LIST_TYPE_NORMAL);

	c=Args;
	while ((*c==' ') && (*c!=0x00)) c++;

	/*The first arg is the timeout length*/
	c2=strchr(c, ',');
	if (!c2){
		printf("Expected \",\"\n");
		printf("Usage response=bns(<timeout>, <GreenList>)\n");
		free(data);
		return NULL;
	}
	*c2=0x00;
	c2++;
	data->TimeOut=atoi(c);
	
#ifdef DEBUG
	printf("Timeout set to %i\n",data->TimeOut);
#endif	

	/*The second arg is the green list*/
	c=c2;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!AddIPRanges(data->GreenList, c)){
		printf("Couldn't understand Green List (%s)\n",c);
		free(data);
		return NULL;
	}
	
	return data;
}


/******************************************
* handle informational messages
******************************************/
int BNSMessage(char* Message, void* Data){

#ifdef DEBUGPATH
	printf("In BNSMessage\n");
#endif

	return TRUE;
}

/******************************************
* Reroute this IP
******************************************/
int BNSAction(int RuleNum, int PacketSlot, void* Data){
	ActionBNSRec*		data;
	PacketRec*			p;
	IPData*				IP;
	char				Message[512];
	
#ifdef DEBUGPATH
	printf("In BNSAction\n");
#endif

#ifdef DEBUG
	printf("Applying an BNS action\n");
#endif

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
	data=(ActionBNSRec*)Data;

	if (IsInList(data->GreenList, ntohl(IP->Header->saddr))){
#ifdef DEBUG
		printf("This is in the green list\n");
#endif	
		return FALSE;
	}
						
	snprintf(Message, 512,"Rerouting %s to Honeypot for %i seconds",inet_ntoa(*(struct in_addr*)&IP->Header->saddr),data->TimeOut);
	LogMessage(Message);
				
	return AddRangeTime(BNSRerouteList, ntohl(IP->Header->saddr), ntohl(IP->Header->saddr), p->tv.tv_sec+data->TimeOut);
}

/********************************
* Set up the bns routing stuff
********************************/
int InitActionBNS(){
	int ActionID;

#ifdef DEBUGPATH
	printf("In InitActionBNS\n");
#endif

	ActionID=CreateAction("bns");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action BNS\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=BNSAction;
	Globals.ActionItems[ActionID].MessageFunc=BNSMessage;
	Globals.ActionItems[ActionID].ParseArgs=BNSParseArgs;

	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
