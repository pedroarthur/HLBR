#include "action_drop.h"
#include "../packets/packet.h"
#include "../engine/session.h"
#include <stdio.h>

//#define DEBUG

extern GlobalVars	Globals;

/********************************
* Drop this packet
********************************/
int DropAction(int RuleNum, int PacketSlot, void* Data){
	PacketRec*	p;


	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	p->PassRawPacket=FALSE;
//	if (p->Status == PACKET_STATUS_BLOCKED)
//		TCPRemount_unblock(PacketSlot, TRUE);
	
	return TRUE;
}

/********************************
* Set up the dropping mechanism
********************************/
int InitActionDrop(){
	int ActionID;

	DEBUGPATH;

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
