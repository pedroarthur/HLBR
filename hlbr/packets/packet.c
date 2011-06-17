#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>

#include "packet.h"
#include "../engine/bits.h"
#include "../engine/hlbr.h"
#include "../engine/hlbrlib.h"

#include "packet_linux_raw.h"
#include "packet_obsd_bpf.h"
#include "packet_osx_bpf.h"
#include "packet_tcpdump.h"
#include "packet_solaris_dlpi.h"

#include "../routes/route_macfilter.h"

struct {
	Stack* Idle;
	Stack* Allocated;

	Stack* Processing;
	Queue* Pending;

	Stack* Saved;

	/* For performing actions */
	Queue* Waiting;
	Stack* Performing;

	/* For sending packet */
	Queue** Scheduling;
	Stack* Sending;
} PacketQueue;

extern GlobalVars Globals;

int		PacketLockID = 0;
unsigned int 	CurPacketNum = 0;

//#define DEBUG
//#define DEBUGPACKETS
//#define DEBUGLOCKS
// #define DEBUG_SCHEDULE

int GetPacketTypeByName(char* Name){

	DEBUGPATH;

	if (strcasecmp(Name, "linux_raw")==0){
		return PACKET_TYPE_LINUX_RAW;
	}else if (strcasecmp(Name, "pcap")==0){
		return PACKET_TYPE_PCAP;
	}else if (strcasecmp(Name, "obsd_bpf")==0){
		return PACKET_TYPE_OBSD_BPF;
	}else if (strcasecmp(Name, "osx_bpf")==0){
		return PACKET_TYPE_OSX_BPF;
	}else if (strcasecmp(Name, "tcpdump")==0){
		return PACKET_TYPE_TCPDUMP;
	}else if (strcasecmp(Name, "solaris_dlpi")==0){
		return PACKET_TYPE_SOLARIS_DLPI;
	}

	return PACKET_TYPE_NONE;
}

int GetPacketProtoByName(char* Name){

	DEBUGPATH;

	if (strcasecmp(Name, "ethernet")==0){
		return PACKET_PROTO_ETHERNET;
	}

	return PACKET_PROTO_NONE;
}

int GetPacketRoleByName(char* Name){

	DEBUGPATH;

	if (strcasecmp(Name, "normal")==0){
		return PACKET_ROLE_NORMAL;
	}else if (strcasecmp(Name, "external")==0){
		return PACKET_ROLE_EXTERNAL;
	}else if (strcasecmp(Name, "internal")==0){
		return PACKET_ROLE_INTERNAL;
	}else if (strcasecmp(Name, "honey")==0){
		return PACKET_ROLE_HONEY;
	}

	return PACKET_ROLE_NORMAL;
}

int OpenInterface(int InterfaceID){
	InterfaceRec*	Interface;

	DEBUGPATH;

#ifdef DEBUG
	printf("Opening Interface %s\n",Globals.Interfaces[InterfaceID].Name);
#endif

	Interface=&Globals.Interfaces[InterfaceID];
	switch (Interface->Type){
#ifdef _LINUX_
		case PACKET_TYPE_LINUX_RAW:
			return OpenInterfaceLinuxRaw(InterfaceID);
#endif
#ifdef _OBSD_
		case PACKET_TYPE_OBSD_BPF:
			return OpenInterfaceOBSDBPF(InterfaceID);
#endif		
#ifdef _OSX_
		case PACKET_TYPE_OSX_BPF:
			return OpenInterfaceOSXBPF(InterfaceID);
#endif
		case PACKET_TYPE_TCPDUMP:
			return OpenInterfaceTCPDump(InterfaceID);
#ifdef _SOLARIS_
		case PACKET_TYPE_SOLARIS_DLPI:
			return OpenInterfaceSolarisDLPI(InterfaceID);
#endif
		default:
			printf("Invalid interface type for \"%s\" try specifying type=<type>\n", Interface->Name);
			return FALSE;
	}

	return FALSE;
}

int OpenInterfaces(){
	int 	i;

	DEBUGPATH;

	for (i=0;i<Globals.NumInterfaces;i++)
		if (!OpenInterface(i)) return FALSE;

	return TRUE;
}

int ReadPacket(int InterfaceID){
	InterfaceRec*	Interface;

	DEBUGPATH;

	Interface=&Globals.Interfaces[InterfaceID];

	switch (Interface->Type){
#ifdef _LINUX_
		case PACKET_TYPE_LINUX_RAW:
			return ReadPacketLinuxRaw(InterfaceID);
#endif
#ifdef _OBSD_
		case PACKET_TYPE_OBSD_BPF:
			return ReadPacketOBSDBPF(InterfaceID);
#endif
#ifdef _OSX_
		case PACKET_TYPE_OSX_BPF:
			return ReadPacketOSXBPF(InterfaceID);
#endif
		case PACKET_TYPE_TCPDUMP:
			return ReadPacketTCPDump(InterfaceID);
#ifdef _SOLARIS_
		case PACKET_TYPE_SOLARIS_DLPI:
			return ReadPacketSolarisDLPI(InterfaceID);
#endif
		default:
			printf("ReadPacket: I don't know what type of interface that is (%i)\n", Interface->Type);
			return FALSE;
	}

	return FALSE;
}

int WritePacket(int PacketSlot){
	InterfaceRec*		Interface;
	int			InterfaceID;
	unsigned char*		Packet;
	int			PacketLen;

	int			i;

	DEBUGPATH;

	InterfaceID = Globals.Packets[PacketSlot].TargetInterface;
	Packet = Globals.Packets[PacketSlot].RawPacket;
	PacketLen = Globals.Packets[PacketSlot].PacketLen;

	if (InterfaceID != INTERFACE_BROADCAST){
		Interface=&Globals.Interfaces[InterfaceID];

		switch (Interface->Type){
			case PACKET_TYPE_LINUX_RAW:
#ifdef _LINUX_
#ifdef DEBUG
				printf("1Normal: Sending out interface %i(%s)\n",InterfaceID, Globals.Interfaces[InterfaceID].Name);
#endif
				return WritePacketLinuxRaw(InterfaceID, Packet, PacketLen);
#endif
#ifdef _OBSD_
			case PACKET_TYPE_OBSD_BPF:
#ifdef DEBUG
				printf("2Normal: Sending out interface %i(%s)\n",InterfaceID, Globals.Interfaces[InterfaceID].Name);
#endif
				return WritePacketOBSDBPF(InterfaceID, Packet, PacketLen);
#endif
#ifdef _OSX_
			case PACKET_TYPE_OSX_BPF:
#ifdef DEBUG
				printf("3Normal: Sending out interface %i(%s)\n",InterfaceID, Globals.Interfaces[InterfaceID].Name);
#endif
				return WritePacketOSXBPF(InterfaceID, Packet, PacketLen);			
#endif
			case PACKET_TYPE_TCPDUMP:
#ifdef DEBUG
				printf("4Normal: Sending out interface %i(%s)\n",InterfaceID, Globals.Interfaces[InterfaceID].Name);
#endif
				return WritePacketTCPDump(InterfaceID, Packet, PacketLen);
#ifdef _SOLARIS_
			case PACKET_TYPE_SOLARIS_DLPI:
#ifdef DEBUG
				printf("3Normal: Sending out interface %i(%s)\n",InterfaceID, Globals.Interfaces[InterfaceID].Name);
#endif
				return WritePacketSolarisDLPI(InterfaceID, Packet, PacketLen);
#endif
			default:
				printf("WritePacket: I don't know what type of interface that is (%i)\n", Interface->Type);
				return FALSE;
		}
	}else{
		for (i=0;i<Globals.NumInterfaces;i++){
			if (i != InterfaceID){
				Interface=&Globals.Interfaces[i];

				switch (Interface->Type){
#ifdef _LINUX_
					case PACKET_TYPE_LINUX_RAW:
#ifdef DEBUG
						printf("Broadcast: Sending out interface %i(%s)\n",i, Globals.Interfaces[i].Name);
#endif
						WritePacketLinuxRaw(i, Packet, PacketLen);
						break;
#endif
#ifdef _OBSD_
					case PACKET_TYPE_OBSD_BPF:
#ifdef DEBUG
						printf("Broadcast: Sending out interface %i(%s)\n",i, Globals.Interfaces[i].Name);
#endif
						WritePacketOBSDBPF(i, Packet, PacketLen);
						break;
#endif
#ifdef _OSX_
					case PACKET_TYPE_OSX_BPF:
#ifdef DEBUG
						printf("Broadcast: Sending out interface %i(%s)\n",i, Globals.Interfaces[i].Name);
#endif
						WritePacketOSXBPF(i, Packet, PacketLen);
						break;
#endif
					case PACKET_TYPE_TCPDUMP:
#ifdef DEBUG
						printf("Broadcast: Sending out interface %i(%s)\n",i, Globals.Interfaces[i].Name);
#endif
						WritePacketTCPDump(i, Packet, PacketLen);
						break;
#ifdef _SOLARIS_
					case PACKET_TYPE_SOLARIS_DLPI:
#ifdef DEBUG
						printf("Broadcast: Sending out interface %i(%s)\n",i, Globals.Interfaces[i].Name);
#endif
						WritePacketSolarisDLPI(i, Packet, PacketLen);
						break;
#endif
					default:
						printf("WritePacket2: I don't know what type of interface that is (%i) Interface %i\n", Interface->Type, i);
						return FALSE;
				}
			}
		}
	}

	return FALSE;
}

void PrintPacketCount () {
	int i;

	printf("There are:\n");
	printf("  %i Idle\n", StackGetSize(PacketQueue.Idle));
	printf("  %i Pending\n", QueueGetSize(PacketQueue.Pending));
	printf("  %i Saved\n", StackGetSize(PacketQueue.Saved));
	printf("  %i Allocated\n", StackGetSize(PacketQueue.Allocated));
	printf("  %i Processing\n", StackGetSize(PacketQueue.Processing));
	printf("  %i Waiting\n", QueueGetSize(PacketQueue.Waiting));
	printf("  %i Performing\n", StackGetSize(PacketQueue.Performing));

	for (i = 0 ; i < Globals.NumInterfaces ; i++) {
		printf("  %i Beeing Scheduled on interface %s\n",
		       QueueGetSize (PacketQueue.Scheduling[i]),
		       Globals.Interfaces[i].Name);
	}

	printf("  %i Sending\n", StackGetSize(PacketQueue.Sending));
}

int InitPacketQueue (int max_packets) {
	int i;

	DEBUGPATH;

	PacketQueue.Idle = StackNew ();
	PacketQueue.Allocated = StackNew ();
	PacketQueue.Processing = StackNew ();
	PacketQueue.Saved = StackNew ();
	PacketQueue.Pending = QueueNew ();
	PacketQueue.Waiting = QueueNew ();
	PacketQueue.Performing = StackNew ();
	PacketQueue.Sending = StackNew ();

	PacketQueue.Scheduling = (Queue **) calloc (Globals.NumInterfaces, sizeof(Queue*));

	if (!PacketQueue.Idle ||
	    !PacketQueue.Allocated ||
	    !PacketQueue.Processing ||
	    !PacketQueue.Saved ||
	    !PacketQueue.Pending ||
	    !PacketQueue.Waiting ||
	    !PacketQueue.Performing ||
	    !PacketQueue.Scheduling ||
	    !PacketQueue.Sending)
	{
		fprintf (stderr, "%s: Couldn't allocate memory for Packets tickets\n", __FUNCTION__);
		return FALSE;
	}

	for (i = 0 ; i < Globals.NumInterfaces ; i++){
		PacketQueue.Scheduling[i] = QueueNew ();

		if (!PacketQueue.Scheduling[i]) {
			fprintf (stderr, "%s: Couldn't allocate memory for Packets tickets\n", __FUNCTION__);
			return FALSE;
		}
	}

	for (i = 0 ; i < max_packets ; i++){
		if (!StackPushData(PacketQueue.Idle, (void*)i)) {
			fprintf (stderr, "%s: Couldn't allocate memory for Packets tickets\n", __FUNCTION__);
			return FALSE;
		}

		Globals.Packets[i].PacketSlot = i;
		StackPost (PacketQueue.Idle);
	}
}

int GetEmptyPacket()
{
	PacketRec*	Packet;
	int		PacketSlot;
	Node* 		aux;

	DEBUGPATH;

	StackWait (PacketQueue.Idle);
	aux = StackPopNode(PacketQueue.Idle);

	PacketSlot = (int) NodeGetData(aux);
	StackPushNode (PacketQueue.Allocated, aux);

	Packet = &Globals.Packets[PacketSlot];

	memset(Packet->RuleBits, 0xFF, MAX_RULES/8);
	Packet->Status = PACKET_STATUS_ALLOCATED;
	Packet->PacketNum = CurPacketNum++;
	Packet->PacketLen = 0;
	Packet->SaveCount = 0;
	Packet->tv.tv_sec = 0;
	Packet->tv.tv_usec = 0;
	Packet->NumDecoderData = 0;
	Packet->PassRawPacket = TRUE;
	Packet->RawPacket = Packet->TypicalPacket;
	Packet->LargePacket = FALSE;

	return PacketSlot;
}

int AddPacketToPending(int PacketSlot) {
	Node* aux;

	DEBUGPATH;

	Globals.Packets[PacketSlot].Status = PACKET_STATUS_PENDING;

	aux = StackPopNode(PacketQueue.Allocated);

	NodeSetData(aux,(void*)PacketSlot);

	QueueAddNode(PacketQueue.Pending, aux);
	QueuePost(PacketQueue.Pending);

	return TRUE;
}

int PopFromPending() {
	int 	PacketSlot = PACKET_NONE;
	Node*	aux;

	DEBUGPATH;

	if (!QueueWait(PacketQueue.Pending)) {
		return PACKET_NONE;
	}

	aux = QueueGetNode (PacketQueue.Pending);

	PacketSlot = (int)NodeGetData (aux);
	Globals.Packets[PacketSlot].Status = PACKET_STATUS_PROCESSING;

	StackPushNode (PacketQueue.Processing, aux);

	return PacketSlot;
}

int AddPacketToWaiting (int PacketSlot) {
	Node* aux;

	DEBUGPATH;

	switch (Globals.Packets[PacketSlot].Status) {
		case PACKET_STATUS_PROCESSING:
			aux = StackPopNode (PacketQueue.Processing);
			break;

		case PACKET_STATUS_ALLOCATED:
			aux = StackPopNode (PacketQueue.Allocated);
			break;

		default:
			return FALSE;
	}

	NodeSetData (aux,(void*)PacketSlot);
	Globals.Packets[PacketSlot].Status = PACKET_STATUS_WAITING;

	QueueAddNode (PacketQueue.Waiting, aux);
	QueuePost(PacketQueue.Waiting);

	return TRUE;
}

int PopFromWaiting () {
	Node* aux;
	int PacketSlot;

	DEBUGPATH;

	if (!QueueWait(PacketQueue.Waiting))
		return PACKET_NONE;

	aux = QueueGetNode (PacketQueue.Waiting);

	PacketSlot = (int)NodeGetData (aux);
	Globals.Packets[PacketSlot].Status = PACKET_STATUS_PERFORMING;

	StackPushNode (PacketQueue.Performing, aux);

	return PacketSlot;
}

int SchedulePacket (int PacketSlot) {
	Node* aux;
	PacketRec* packet = &Globals.Packets[PacketSlot];

	DEBUGPATH;

	if (packet->TargetInterface != INTERFACE_BROADCAST) {
#ifdef DEBUG_SCHEDULE
		fprintf (stderr, "%s: sending packet %d\n", __FUNCTION__, PacketSlot);
		fprintf (stderr, "%s: TargetInterface: %d (%s)\n", __FUNCTION__, packet->TargetInterface,
									Globals.Interfaces[packet->TargetInterface].Name);
#endif

		switch (packet->Status) {
			case PACKET_STATUS_PROCESSING:
				aux = StackPopNode (PacketQueue.Processing);
				break;

			case PACKET_STATUS_PERFORMING:
				aux = StackPopNode (PacketQueue.Performing);
				break;

			case PACKET_STATUS_ALLOCATED:
				aux = StackPopNode (PacketQueue.Allocated);
				break;
		}

		NodeSetData (aux,(void*) PacketSlot);

		packet->Status = PACKET_STATUS_SCHEDULING;

		QueueAddNode (PacketQueue.Scheduling[packet->TargetInterface], aux);
		QueuePost (PacketQueue.Scheduling[packet->TargetInterface]);
	} else {
		MacFilterNode *node = (MacFilterNode *) Globals.Interfaces[packet->InterfaceNum].RouteData;
		PacketRec clone;

		int i;

#ifdef DEBUG_SCHEDULE
		fprintf (stderr, "%s: sending packet %d through BROADCAST Interface\n", __FUNCTION__, PacketSlot);

		for (i = 0 ; i < node->IfacesCount ; i++)
			fprintf (stderr, "%s: Target interface %d: %d (%s)\n", __FUNCTION__, i, node->IfaceArray[i],
										Globals.Interfaces[node->IfaceArray[i]].Name);
#endif

		if (!ClonePacket (&clone, packet)) {
			fprintf (stderr, "%s: Can't clone packet for broadcasting\n", __FUNCTION__);

			ReturnEmptyPacket (PacketSlot);
			return FALSE;
		}

		if (node->IfaceArray[0] == clone.InterfaceNum) {
			packet->TargetInterface = node->IfaceArray[1];
			i = 2;
		} else {
			packet->TargetInterface = node->IfaceArray[0];
			i = 1;
		}

		SchedulePacket (PacketSlot);

		while(i < node->IfacesCount) {
			if (node->IfaceArray[i] != clone.InterfaceNum){
				PacketSlot = GetEmptyPacket();
				packet = &Globals.Packets[PacketSlot];

				if (!ClonePacket(packet, &clone)) {
					ReturnEmptyPacket (PacketSlot);
					return FALSE;
				}

				packet->TargetInterface = node->IfaceArray[i];

				SchedulePacket(PacketSlot);
			}

			i++;
		}
	}

	return TRUE;
}

int GetScheduledPacket (int InterfaceID) {
	Node* aux;
	int PacketSlot;

	DEBUGPATH;

	QueueWait (PacketQueue.Scheduling[InterfaceID]);
	aux = QueueGetNode (PacketQueue.Scheduling[InterfaceID]);

	PacketSlot = (int)NodeGetData (aux);
	Globals.Packets[PacketSlot].Status = PACKET_STATUS_SENDING;

	StackPushNode (PacketQueue.Sending, aux);

	return PacketSlot;
}

void SavePacket(int PacketSlot) {
	Globals.Packets[PacketSlot].SaveCount++;
}

void UnsavePacket(int PacketSlot) {
	if (--Globals.Packets[PacketSlot].SaveCount < 1)
		ReturnEmptyPacket(PacketSlot);
}

/**
 * Return a packet struct to the pool for reuse.
 */
void ReturnEmptyPacket(int PacketSlot) {
	int 		i;
	PacketRec*	p;
	Node*		aux;

	DEBUGPATH;

	if (Globals.Packets[PacketSlot].SaveCount < 1) {
		p = &Globals.Packets[PacketSlot];

		if  (p->LargePacket){
			free(p->RawPacket);
			p->RawPacket = p->TypicalPacket;
			p->LargePacket = FALSE;
		}

		for (i = 0 ; i < p->NumDecoderData ; i++){
			if (p->DecoderInfo[p->DecodersUsed[i]].Data)
				Globals.Decoders[p->DecodersUsed[i]].Free (p->DecoderInfo[p->DecodersUsed[i]].Data);

			p->DecoderInfo[p->DecodersUsed[i]].Data=NULL;
		}

		switch(Globals.Packets[PacketSlot].Status){
			case PACKET_STATUS_ALLOCATED:
				aux = StackPopNode (PacketQueue.Allocated);
				break;

			case PACKET_STATUS_PROCESSING:
				aux = StackPopNode (PacketQueue.Processing);
				break;

			case PACKET_STATUS_SAVED:
				aux = StackPopNode (PacketQueue.Saved);
				break;

			case PACKET_STATUS_PERFORMING:
				aux = StackPopNode (PacketQueue.Performing);
				break;

			case PACKET_STATUS_SENDING:
				aux = StackPopNode (PacketQueue.Sending);
				break;
		}

		NodeSetData (aux,(void*)PacketSlot);

		StackPushNode (PacketQueue.Idle, aux);
		StackPost (PacketQueue.Idle);
	} else if (Globals.Packets[PacketSlot].Status == PACKET_STATUS_PROCESSING) {
		Globals.Packets[PacketSlot].Status = PACKET_STATUS_SAVED;
		StackPushNode(PacketQueue.Saved, StackPopNode(PacketQueue.Processing));
	}

#ifdef DEBUG_PACKETS
	PrintPacketCount();
#endif
}

int StartInterfaceThread(int InterfaceID) {
	InterfaceRec*	Interface;

	DEBUGPATH;

	Interface = &Globals.Interfaces[InterfaceID];

	switch(Interface->Type) {
#ifdef _LINUX_
		case PACKET_TYPE_LINUX_RAW:
			return LoopThreadLinuxRaw(InterfaceID);
#endif
#ifdef _OBSD_
		case PACKET_TYPE_OBSD_BPF:
			return LoopThreadOBSDBPF(InterfaceID);
#endif
#ifdef _OSX_
		case PACKET_TYPE_OSX_BPF:
			return LoopThreadOSXBPF(InterfaceID);
#endif
		case PACKET_TYPE_TCPDUMP:
			return LoopThreadTCPDump(InterfaceID);
#ifdef _SOLARIS_
		case PACKET_TYPE_SOLARIS_DLPI:
			return LoopThreadSolarisDLPI(InterfaceID);
#endif
		default:
			printf("I can't start a thread for that interface type\n");
			return FALSE;
	}

	return TRUE;
}

/**********************************************
* Check to see if a rule is still active
**********************************************/
inline int RuleIsActive(int PacketSlot, int RuleNum){
	DEBUGPATH;

	return GetBit(Globals.Packets[PacketSlot].RuleBits, Globals.NumRules, RuleNum);	
}

/**********************************************
* Mark a rule as no longer active
**********************************************/
inline int SetRuleInactive(int PacketSlot, int RuleNum){
	DEBUGPATH;

	SetBit(Globals.Packets[PacketSlot].RuleBits, Globals.NumRules, RuleNum, 0);

	return TRUE;
}

/**********************************************
* Given a name, return the interface ID
**********************************************/
int GetInterfaceByName(char* Name){
	int	i;

	DEBUGPATH;

	for (i = 0 ; i < Globals.NumInterfaces ; i++){
		if (strcasecmp(Name, Globals.Interfaces[i].Name) == 0){
			return i;
		}
	}

	return INTERFACE_NONE;
}

/**
* Clone two packets, but preserves decoders and rule bitmaps
*/

int ClonePacket (PacketRec* dst, PacketRec* src) {
	dst->TargetInterface = src->TargetInterface;
	dst->InterfaceNum = src->InterfaceNum;

	dst->LargePacket = src->LargePacket;
	dst->PacketLen = src->PacketLen;

	if (!dst->LargePacket) {
		dst->RawPacket = dst->TypicalPacket;
	} else {
		dst->RawPacket = (char *) malloc (dst->PacketLen * sizeof(char));

		if (!dst->RawPacket) {
			fprintf (stderr, "%s: Can't allocate memory for large packet cloning\n", __FUNCTION__);
			return FALSE;
		}
	}

	memcpy (dst->RawPacket, src->RawPacket, dst->PacketLen);
	memcpy (&dst->tv, &src->tv, sizeof(struct timeval));

	return TRUE;
}

#ifdef DEBUG_SCHEDULE
#undef DEBUG_SCHEDULE
#endif