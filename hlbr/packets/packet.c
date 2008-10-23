#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>

#include "packet.h"
#include "../engine/bits.h"
#include "../engine/hlbr.h"
//#include "../mangle/mangle.h"

/*****************************************
* Includes for all the interface types
* goes here
*****************************************/
#include "packet_linux_raw.h"
#include "packet_obsd_bpf.h"
#include "packet_osx_bpf.h"
#include "packet_tcpdump.h"
#include "packet_solaris_dlpi.h"

typedef struct qn {
	int p;
	struct qn *next;
} QNode;

struct {
	/* Stacks */
	QNode* Idle;
	QNode* Processing;
	QNode* Allocated;
	QNode* Saved;

	/* Queue */
	QNode* PendingFisrt;
	QNode* PendingLast;
} PacketQueue;

extern GlobalVars Globals;

pthread_mutex_t				PacketMutex;
sem_t					PendingSemaphore;
int					PacketLockID=0;
unsigned int 				CurPacketNum=0;

//#define DEBUG
//#define DEBUGPACKETS
//#define DEBUGLOCKS

/**************************************
* Given the name of a packet type,
* return its ID
**************************************/
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

/**************************************
* Given the name of a protocol,
* return its ID
**************************************/
int GetPacketProtoByName(char* Name){

	DEBUGPATH;

	if (strcasecmp(Name, "ethernet")==0){
		return PACKET_PROTO_ETHERNET;
	}

	return PACKET_PROTO_NONE;
}

/**************************************
* Given the name of a role,
* return its ID
**************************************/
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

/******************************************
* Sets an interface up for reading/writing
******************************************/
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


/******************************************
* Open up all the interfaces
******************************************/
int OpenInterfaces(){
	int 	i;

	DEBUGPATH;

	for (i=0;i<Globals.NumInterfaces;i++)
		if (!OpenInterface(i)) return FALSE;

	return TRUE;
}

/******************************************
* Read packet(s) from an interface
* Packets will be put on the pending queue
******************************************/
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

/*****************************************************
* Send off the packet
*****************************************************/
int WritePacket(int PacketSlot){
	InterfaceRec*		Interface;
	int			InterfaceID;
	unsigned char*		Packet;
	int			PacketLen;

	int			i;

	DEBUGPATH;

	InterfaceID=Globals.Packets[PacketSlot].TargetInterface;
	Packet=Globals.Packets[PacketSlot].RawPacket;
	PacketLen=Globals.Packets[PacketSlot].PacketLen;

	if (InterfaceID!=INTERFACE_BROADCAST){
		Interface=&Globals.Interfaces[InterfaceID];
/*	
#ifdef DEBUG
		printf("Applying mangling to non-broadcast packet\n");
#endif	

		if (!Mangle(PacketSlot, Globals.Packets[PacketSlot].InterfaceNum, InterfaceID)){
#ifdef DEBUG
			printf("Failed to mangle packet\n");
#endif		
			return FALSE;
		}
*/	
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
		/*this is a broadcast packet*/
		for (i=0;i<Globals.NumInterfaces;i++){
			if (i!=InterfaceID){
				Interface=&Globals.Interfaces[i];
/*
#ifdef DEBUG
				printf("Applying mangling to broadcast packet\n");
#endif	

				if (!Mangle(PacketSlot, Globals.Packets[PacketSlot].InterfaceNum, i)){
#ifdef DEBUG
					printf("Failed to mangle packet\n");
#endif		
					break;
				}
*/
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

void InitPacketQueue (int max_packets) {
	int i;
	QNode *aux = NULL;

	DEBUGPATH;

	PacketQueue.Idle = aux = (QNode *) calloc (1, sizeof(QNode));

	if (!aux) {
		fprintf (stderr, "Couldn't allocate memory for Packet 0\n");
		return;
	}

	aux->p = 0;

	for (i = 1 ; i < max_packets ; i++) {
		aux->next = (QNode *) calloc (1, sizeof(QNode));

		if (!aux->next) {
			fprintf (stderr, "Couldn't allocate memory for Packet %d\n", i);
			return;
		}

		aux = aux->next;
		aux->p = i;
	}

	sem_init (&PendingSemaphore, 0, 0);
}

/**
 * Marks a packet as 'pending' (thread safe, called from ReadPacket)
 * Gets called every time a packet gets put on the pending list. Uses a 
 * mutex lock (to avoid problems with threads).
 * This may be called more than once per ReadPacket request.
 * @see ReadPacket
 */
int AddPacketToPending(int PacketSlot) {
	DEBUGPATH;

	Globals.Packets[PacketSlot].Status = PACKET_STATUS_PENDING;

	hlbr_mutex_lock(&PacketMutex, ADD_PACKET_1, &PacketLockID);

	if (!PacketQueue.PendingFisrt) {
		PacketQueue.PendingFisrt = PacketQueue.PendingLast = PacketQueue.Allocated;

		PacketQueue.Allocated = PacketQueue.Allocated->next;
		PacketQueue.PendingFisrt->next = NULL;

		PacketQueue.PendingFisrt->p = PacketSlot;
	} else {
		PacketQueue.PendingLast->next = PacketQueue.Allocated;
		PacketQueue.PendingLast = PacketQueue.Allocated;

		PacketQueue.Allocated = PacketQueue.Allocated->next;

		PacketQueue.PendingLast->next = NULL;
		PacketQueue.PendingLast->p = PacketSlot;
	}

	Globals.PendingCount++;
	Globals.AllocatedCount--;

	hlbr_mutex_unlock(&PacketMutex);

	sem_post (&PendingSemaphore);

	return TRUE;
}

/**
 * Pops a packet off the pending queue
 * Give the caller a packet off the pending queue (marked as 
 * PACKET_STATUS_PENDING)
 */
int PopFromPending() {
	int 	PacketSlot = PACKET_NONE;
	QNode*	aux;

	DEBUGPATH;

	if (sem_wait (&PendingSemaphore)) {
		return PACKET_NONE;
	}

	hlbr_mutex_lock(&PacketMutex, ADD_PACKET_1, &PacketLockID);

	aux = PacketQueue.PendingFisrt;
	PacketQueue.PendingFisrt = PacketQueue.PendingFisrt->next;

	aux->next = PacketQueue.Processing;
	PacketQueue.Processing = aux;

	PacketSlot = aux->p;

	if (!PacketQueue.PendingFisrt && PacketQueue.PendingLast)
		PacketQueue.PendingLast = NULL;

	Globals.PendingCount--;
	Globals.ProcessingCount++;

	hlbr_mutex_unlock(&PacketMutex);

	Globals.Packets[PacketSlot].Status = PACKET_STATUS_PROCESSING;

	return PacketSlot;
}

/**
 * Get an emoty, unused packet struct from the pool.
 */
int GetEmptyPacket() {
	PacketRec*	Packet;
	int		PacketSlot;

	hlbr_mutex_lock(&PacketMutex, GET_PACKET_1, &PacketLockID);

	if (!PacketQueue.Idle) {
		hlbr_mutex_unlock (&PacketMutex);
		return PACKET_NONE;
	} else {
		QNode* aux = PacketQueue.Idle;
		PacketQueue.Idle = PacketQueue.Idle->next;

		aux->next = PacketQueue.Allocated;
		PacketQueue.Allocated = aux;

		PacketSlot = aux->p;

		Globals.AllocatedCount++;
		Globals.IdleCount--;

		hlbr_mutex_unlock (&PacketMutex);
	}

	Packet = &Globals.Packets[PacketSlot];

	/*initialize the packet*/
	Packet->PacketSlot = PacketSlot;
	Packet->Status = PACKET_STATUS_ALLOCATED;
	memset(Packet->RuleBits, 0xFF, MAX_RULES/8);
	Packet->PacketLen = 0;
	Packet->SaveCount = 0;
	Packet->tv.tv_sec = 0;
	Packet->tv.tv_usec = 0;
	Packet->NumDecoderData = 0;
	Packet->PassRawPacket = TRUE;
	Packet->PacketNum = CurPacketNum++;
	Packet->RawPacket = Packet->TypicalPacket;
	Packet->LargePacket = FALSE;

	return Packet->PacketSlot;
}

/**
 * Return a packet struct to the pool for reuse.
 */
void ReturnEmptyPacket(int PacketSlot) {
	int 		i;
	PacketRec*	p;
	QNode*		aux;

	DEBUGPATH;

	if (Globals.Packets[PacketSlot].SaveCount < 1) {
		p=&Globals.Packets[PacketSlot];

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

		hlbr_mutex_lock(&PacketMutex, RETURN_PACKET_1, &PacketLockID);

		switch(Globals.Packets[PacketSlot].Status){
			case PACKET_STATUS_ALLOCATED:
				aux = PacketQueue.Allocated;
				PacketQueue.Allocated = PacketQueue.Allocated->next;

				Globals.AllocatedCount--;
				break;
			case PACKET_STATUS_PROCESSING:
				aux = PacketQueue.Processing;
				PacketQueue.Processing = PacketQueue.Processing->next;

				Globals.ProcessingCount--;
				break;
			case PACKET_STATUS_SAVED:
				aux = PacketQueue.Saved;
				PacketQueue.Saved = PacketQueue.Saved->next;

				Globals.SavedCount--;
				break;
		}

		aux->next = PacketQueue.Idle;
		PacketQueue.Idle = aux;
		aux->p = PacketSlot;

		Globals.Packets[PacketSlot].Status = PACKET_STATUS_IDLE;

		Globals.IdleCount++;

		hlbr_mutex_unlock(&PacketMutex);
	} else if (Globals.Packets[PacketSlot].Status == PACKET_STATUS_PROCESSING) {
		hlbr_mutex_lock(&PacketMutex, RETURN_PACKET_1, &PacketLockID);

		aux = PacketQueue.Processing;
		PacketQueue.Processing = PacketQueue.Processing->next;

		aux->next = PacketQueue.Saved;
		PacketQueue.Saved = aux;

		Globals.Packets[PacketSlot].Status = PACKET_STATUS_SAVED;

		Globals.ProcessingCount--;
		Globals.SavedCount++;

		hlbr_mutex_unlock(&PacketMutex);
	}

#ifdef DEBUG_PACKETS
	printf("There are:\n");
	printf("  %i Idle\n",Globals.IdleCount);
	printf("  %i Pending\n",Globals.PendingCount);
	printf("  %i Saved\n",Globals.SavedCount);
	printf("  %i Allocated\n",Globals.AllocatedCount);
	printf("  %i Processing\n",Globals.ProcessingCount);
	printf("  %i The Total sum\n", Globals.IdleCount+Globals.PendingCount+Globals.SavedCount+Globals.AllocatedCount+Globals.ProcessingCount);
#endif
}

/**
 * Start a new dedicated thread to read the network interface.
 */
int StartInterfaceThread(int InterfaceID)
{
	InterfaceRec*	Interface;

	DEBUGPATH;

#ifndef HAS_THREADS
	return FALSE;
#else
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
#endif
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
