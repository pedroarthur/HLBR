/*
	gcc -shared mod_example.c -o mod_example.so
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "../engine/hogwash.h"
#include "module.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include <string.h>
#include <netinet/in.h>

#define DEBUG
#define DEBUGPATH

GlobalVars*	HogwashGlobals;

int	IPDecoderID;
int TCPDecoderID;

char ExampleMessage[1024];

/*******************************************
* Set some values on the module
*******************************************/
int ExampleParseArg (char* Arg){
#ifdef DEBUGPATH
	printf("In ExampleParseArg\n");
#endif

	while (*Arg==' ') Arg++;
	
	if (strncasecmp(Arg, "message=",8)==0){
		snprintf(ExampleMessage, 1024, Arg+8);
#ifdef DEBUG	
		printf("Setting ExampleMessage to \"%s\"\n",ExampleMessage);
#endif		
		return TRUE;
	}else{
		printf("I don't understand \"%s\"\n", Arg);
		return FALSE;
	}

	return TRUE;
}

/************************************
* Called with every TCP packet
************************************/
void ExampleFunc(int PacketSlot){
	IPData*			IData;
	TCPData*		TData;
	unsigned short	DPort;
	unsigned short	SPort;
	PacketRec*		p;

#ifdef DEBUGPATH
	printf("In ExampleFunc\n");
#endif

	p=&HogwashGlobals->Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
#ifdef DEBUG
		printf("Couldn't get IP Header\n");
#endif	
		return;
	}

	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)){
#ifdef DEBUG
		printf("Couldn't get TCP Header\n");
#endif	
		return;
	}
	SPort=ntohs(TData->Header->source);
	DPort=ntohs(TData->Header->dest);
	
}

/****************************************
* This gets called once at startup
****************************************/
int Example_Init(GlobalVars* g){
	int	ModuleID;
		
	HogwashGlobals=g;

#ifdef DEBUGPATH
	printf("In Example_Init\n");
#endif

	ModuleID=CreateModule("example");
	if(ModuleID==MODULE_NONE) return FALSE;
	
	if (!BindModuleToDecoder(ModuleID, "TCP")){
		printf("Failed to bind example Module to TCP\n");
		return FALSE;
	}
	
	HogwashGlobals->Modules[ModuleID].ParseArg=ExampleParseArg;
	HogwashGlobals->Modules[ModuleID].ModuleFunc=ExampleFunc;

	IPDecoderID=GetDecoderByName("IP");
	TCPDecoderID=GetDecoderByName("TCP");
	
	return TRUE;
}

