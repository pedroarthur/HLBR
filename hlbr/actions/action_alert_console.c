#include "action_alert_console.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../engine/hlbr.h"

//#define DEBUG

extern GlobalVars	Globals;

#ifdef MTHREADS
pthread_mutex_t		ConsoleMutex;
int			ConsoleLockID;
#endif

/******************************************
* handle info messages
******************************************/
int AlertConsoleMessage(char* Message, void* Data){

	DEBUGPATH;
#ifdef MTHREADS
	hlbr_mutex_lock (&ConsoleMutex, 0, &ConsoleLockID);
#endif
	printf("%s\n",Message);
#ifdef MTHREADS
	hlbr_mutex_unlock (&ConsoleMutex);
#endif
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
#ifdef MTHREADS
	hlbr_mutex_lock (&ConsoleMutex, 0, &ConsoleLockID);
#endif
	printf("%s ", Buff);

	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	printf("%s\n",Buff);
#ifdef MTHREADS
	hlbr_mutex_unlock (&ConsoleMutex);
#endif

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
