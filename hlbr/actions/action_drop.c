#include "action_drop.h"
#include <stdio.h>

//#define DEBUG

extern GlobalVars	Globals;

/********************************
* Drop this packet
********************************/
int DropAction(int RuleNum, int PacketSlot, void* Data){
	PacketRec*	p;


#ifdef DEBUGPATH
	printf("In DropAction\n");
#endif

#ifdef DEBUG
	printf("Dropping\n");
#endif
	p=&Globals.Packets[PacketSlot];
	p->PassRawPacket=FALSE;
	if (p->Status == PACKET_STATUS_BLOCKED)
		TCPStream_unblock(PacketSlot, TRUE);
	
	return TRUE;
}

/********************************
* Set up the dropping mechanism
********************************/
int InitActionDrop(){
	int ActionID;

#ifdef DEBUGPATH
	printf("In InitActionDrop\n");
#endif

	ActionID=CreateAction("drop");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action drop\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=DropAction;

	return TRUE;
}
