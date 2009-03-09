#include "action_alert_console.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../engine/hlbr.h"

//#define DEBUG

extern GlobalVars	Globals;

pthread_mutex_t		ConsoleMutex;

/******************************************
* handle info messages
******************************************/
int AlertConsoleMessage(char* Message, void* Data){

	DEBUGPATH;

	pthread_mutex_lock (&ConsoleMutex);

	printf("%s\n",Message);

	pthread_mutex_unlock (&ConsoleMutex);

	return TRUE;
}

/******************************************
* write the alert message to the console
******************************************/
int AlertConsoleAction(int RuleNum, int PacketSlot, void* Data){
	char		Buff[1024];
	PacketRec*	p;
	
	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	pthread_mutex_lock (&ConsoleMutex);

	printf("%s ", Buff);

	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	printf("%s\n",Buff);

	pthread_mutex_unlock (&ConsoleMutex);

	return TRUE;
}

/********************************
* Set up the alert console stuff
********************************/
int InitActionAlertConsole(){
	int ActionID;

	DEBUGPATH;

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
