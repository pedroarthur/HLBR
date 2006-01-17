#include "action_alert_console.h"
#include <stdio.h>
#include "../engine/message.h"

//#define DEBUG

extern GlobalVars	Globals;

/******************************************
* handle info messages
******************************************/
int AlertConsoleMessage(char* Message, void* Data){
#ifdef DEBUGPATH
	printf("In AlertConsoleMessage\n");
#endif

	printf("%s\n",Message);
	
	return TRUE;
}

/******************************************
* write the alert message to the console
******************************************/
int AlertConsoleAction(int RuleNum, int PacketSlot, void* Data){
	char		Buff[1024];
	PacketRec*	p;
	
#ifdef DEBUGPATH
	printf("In AlsertConsoleAction\n");
#endif

#ifdef DEBUG
	printf("Writing to the console\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	printf("%s ", Buff);

	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	printf("%s\n",Buff);
	
	return TRUE;
}

/********************************
* Set up the alert console stuff
********************************/
int InitActionAlertConsole(){
	int ActionID;

#ifdef DEBUGPATH
	printf("In InitActionAlertConsole\n");
#endif

	ActionID=CreateAction("alert console");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action alert console\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=AlertConsoleAction;
	Globals.ActionItems[ActionID].MessageFunc=AlertConsoleMessage;

	return TRUE;
}
