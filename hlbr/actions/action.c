#include "action.h"
#include <stdio.h>
#include <string.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif
#include "../packets/packet.h"
/************include plugins here**********/
#include "action_drop.h"
#include "action_alert_console.h"
#include "action_alert_file.h"
#include "action_dump_packet.h"
#include "action_route_sip.h"
#include "action_bns.h"
#include "action_alert_syslog.h"
#include "action_alert_email.h"
#include "action_alert_socket.h"
#include "action_alert_listensocket.h"

//#define DEBUG

extern GlobalVars Globals;

/**********************************
* Set up all the actions
**********************************/
int InitActions(){

  DEBUGPATH;

	if (!InitActionDrop()) return FALSE;
	if (!InitActionAlertConsole()) return FALSE;
	if (!InitActionAlertFile()) return FALSE;
	if (!InitActionDumpPacket()) return FALSE;
	if (!InitActionRouteSIP()) return FALSE;
	if (!InitActionBNS()) return FALSE;
	if (!InitActionAlertSyslog()) return FALSE;
	if (!InitActionAlertEMail()) return FALSE;
	if (!InitActionAlertSocket()) return FALSE;
	if (!InitActionAlertListenSocket()) return FALSE;

	return TRUE;
}

/***********************************
* Given an action's name, return
* its ID
***********************************/
int	GetActionByName(char* Name){
	int	i;

	DEBUGPATH;

	for (i=0;i<Globals.NumActionItems;i++){
		if (strcasecmp(Name, Globals.ActionItems[i].Name)==0){
			return i;
		}
	}

	return ACTION_NONE;
}

/********************************
* Get a New Action from the List
*********************************/
int CreateAction(char* Name){
	int ActionID;
	
	DEBUGPATH;

	/*check to see if this name is already used*/
	ActionID=GetActionByName(Name);
	if (ActionID!=ACTION_NONE){
		printf("Action %s already exists\n",Name);
		return ACTION_NONE;
	}
	
	ActionID=Globals.NumActionItems;
	Globals.NumActionItems++;
	
	bzero(&Globals.ActionItems[ActionID], sizeof(ActionItem));
	Globals.ActionItems[ActionID].ID=ActionID;
	snprintf(Globals.ActionItems[ActionID].Name, MAX_NAME_LEN, Name);
	
#ifdef DEBUG
	printf("Allocated Action \"%s\" at number %i\n",Name, ActionID);
#endif	
	
	return ActionID;
}

/****************************************************
* Expand all the macros for the Message string
****************************************************/
int BuildMessageString(char* Message, int PacketSlot, char* TargetBuff, int TargetBuffLen){

  DEBUGPATH;

	return FALSE;
}

/************************************
* We've got rules matches, perform
* the actions
************************************/
int PerformActions(int PacketSlot){
	int	i;
	int j;
	ActionRec*	Action;
	PacketRec*	p;

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	Globals.AlertCount++;

#ifdef DEBUG
	printf("----------------------------\n");
	printf("Results:\n");
#endif	
	for (i=0;i<Globals.NumRules;i++){
		if (RuleIsActive(PacketSlot, i)){
#ifdef DEBUG		
			printf("Rule %i Matches\n", i);
			printf("ActionID is %i\n",Globals.Rules[i].Action);
			printf("There are %i items\n",Globals.Actions[Globals.Rules[i].Action].NumItems);
#endif			
			/*call all of the actions*/
			Action=&Globals.Actions[Globals.Rules[i].Action];
			for (j=0;j<Action->NumItems;j++){
				if (Globals.ActionItems[Action->ActionItems[j]].ActionFunc)
					Globals.ActionItems[Action->ActionItems[j]].ActionFunc(i,PacketSlot,Globals.Actions[Globals.Rules[i].Action].ActionItemData[j]);
			}
		}
	}
#ifdef DEBUG	
	printf("-----------------------------\n");
#endif
		
	return TRUE;
}

/**
 * Log a message, using all applicable responses in all defined actions.
 * Differentrly from LogMessage, this function searches for all responses in
 * all defined actions and calls every one of them.
 * @see LogMessage
 */
int	LogMessageAllActions(char* Message)
{
	int 		i,j;
	ActionRec*	Action;

	DEBUGPATH;

	for (i = 0; i < Globals.NumActions; i++) {
		Action = &Globals.Actions[i];
		for (j = 0; j < Action->NumItems; j++) {
			if (Globals.ActionItems[Action->ActionItems[j]].MessageFunc)
				Globals.ActionItems[Action->ActionItems[j]].MessageFunc(Message, Globals.Actions[Globals.Rules[i].Action].ActionItemData[j]);
		}
	}
	
	return FALSE;
}
