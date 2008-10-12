#include "packet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../engine/bits.h"
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

extern GlobalVars Globals;

int					LastFreeSlot;
int					LastPendingSlot;

pthread_mutex_t				PacketMutex;
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
	InterfaceRec*	Interface;
	int				i;
	int				InterfaceID;
	unsigned char*	Packet;
	int				PacketLen;

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

/******************************************
* Gets called every time a packet gets
* put on the pending list.
* This may be called more than once per
* ReadPacket request.
******************************************/
int AddPacketToPending(int PacketSlot){
	DEBUGPATH;

	hlbr_mutex_lock(&Globals.Packets[PacketSlot].Mutex, 0, &Globals.Packets[PacketSlot].LockID);
	Globals.Packets[PacketSlot].Status = PACKET_STATUS_PENDING;
	hlbr_mutex_unlock(&Globals.Packets[PacketSlot].Mutex);

	hlbr_mutex_lock(&PacketMutex, ADD_PACKET_1, &PacketLockID);
	LastPendingSlot = PacketSlot;
	Globals.PendingCount++;
	Globals.AllocatedCount--;
	hlbr_mutex_unlock(&PacketMutex);

	return TRUE;
}

/*****************************************
* Give the caller a packet off the pending
* Queue
******************************************/
int PopFromPending(){
	int		PacketSlot;
	int		i;

	DEBUGPATH;

	PacketSlot=PACKET_NONE;

	for (i = 0 ; i < MAX_PACKETS ; i++){
		if (Globals.Packets[i].Status == PACKET_STATUS_PENDING && !hlbr_mutex_trylock(&Globals.Packets[i].Mutex, 0, &Globals.Packets[i].LockID)){
			Globals.Packets[i].Status = PACKET_STATUS_PROCESSING;
			hlbr_mutex_unlock (&Globals.Packets[i].Mutex);

			hlbr_mutex_lock(&PacketMutex, POP_PACKET_1, &PacketLockID);
			Globals.PendingCount--;
			Globals.ProcessingCount++;
			hlbr_mutex_unlock(&PacketMutex);

			return i;
		}
	}

	return PACKET_NONE;
}

/*******************************************
* Get a packet from the pool
********************************************/
int GetEmptyPacket(){
	PacketRec*	Packet;
	int		i;
	int		lf;

	DEBUGPATH;

	Packet=NULL;

	hlbr_mutex_lock(&PacketMutex, GET_PACKET_1, &PacketLockID);
	lf = LastFreeSlot;
	hlbr_mutex_unlock(&PacketMutex);

	for (i = lf; i < MAX_PACKETS ; i++){
		if (Globals.Packets[i].Status == PACKET_STATUS_IDLE && !hlbr_mutex_trylock(&Globals.Packets[i].Mutex, 0, &Globals.Packets[i].LockID)){
#ifdef DEBUG
			printf("Found IDLE packet in slot %i\n",i);
#endif
			Globals.Packets[i].Status = PACKET_STATUS_ALLOCATED;
			hlbr_mutex_unlock (&Globals.Packets[i].Mutex);

			Packet = &Globals.Packets[i];

			break;
		}
	}

	if (!Packet)
		for (i = 0 ; i < lf ; i++){
			if (Globals.Packets[i].Status==PACKET_STATUS_IDLE && !hlbr_mutex_trylock(&Globals.Packets[i].Mutex, 0, &Globals.Packets[i].LockID)){
#ifdef DEBUG
				printf("Found IDLE packet in slot %i\n",i);
#endif
				Globals.Packets[i].Status = PACKET_STATUS_ALLOCATED;
				hlbr_mutex_unlock (&Globals.Packets[i].Mutex);

				Packet = &Globals.Packets[i];

				break;
			}
		}

	if (!Packet){
#ifdef DEBUG
		printf("There were no free packets\n");
#endif
		return PACKET_NONE;
	}

	/*initialize the packet*/
	memset(Packet->RuleBits, 0xFF, MAX_RULES/8);
	Packet->PacketLen = 0;
	Packet->SaveCount = 0;
	Packet->tv.tv_sec = 0;
	Packet->tv.tv_usec = 0;
	Packet->NumDecoderData = 0;
	Packet->PassRawPacket = TRUE;
	Packet->PacketNum = CurPacketNum++;
	Packet->PacketSlot = i;
	Packet->RawPacket = Packet->TypicalPacket;
	Packet->LargePacket = FALSE;

	hlbr_mutex_lock(&PacketMutex, GET_PACKET_1, &PacketLockID);
	Globals.AllocatedCount++;
	Globals.IdleCount--;
	hlbr_mutex_unlock(&PacketMutex);

	return i;
}

/************************************
* Return a packet to the pool
* for reuse
************************************/
void ReturnEmptyPacket(int PacketSlot){
	int 		i;
	PacketRec*	p;

	DEBUGPATH;

	if (Globals.Packets[PacketSlot].SaveCount < 1){
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

		hlbr_mutex_lock(&Globals.Packets[PacketSlot].Mutex, 1, &Globals.Packets[PacketSlot].LockID);
		Globals.Packets[PacketSlot].Status = PACKET_STATUS_IDLE;
		hlbr_mutex_unlock(&Globals.Packets[PacketSlot].Mutex);

		hlbr_mutex_lock(&PacketMutex, RETURN_PACKET_1, &PacketLockID);
		switch(Globals.Packets[PacketSlot].Status){
			case PACKET_STATUS_ALLOCATED:
				Globals.AllocatedCount--;
				break;
			case PACKET_STATUS_PROCESSING:
				Globals.ProcessingCount--;
				break;
		}

		LastFreeSlot = PacketSlot;
		Globals.IdleCount++;
	}else{
		hlbr_mutex_lock(&Globals.Packets[PacketSlot].Mutex, 1, &Globals.Packets[PacketSlot].LockID);
		Globals.Packets[PacketSlot].Status = PACKET_STATUS_SAVED;
		hlbr_mutex_unlock(&Globals.Packets[PacketSlot].Mutex);

		hlbr_mutex_lock(&PacketMutex, RETURN_PACKET_1, &PacketLockID);
		Globals.ProcessingCount--;
		Globals.SavedCount++;
	}

	hlbr_mutex_unlock(&PacketMutex);

#ifdef DEBUG_PACKETS
	printf("There are:\n");
	printf("  %i Idle\n",Globals.IdleCount);
	printf("  %i Pending\n",Globals.PendingCount);
	printf("  %i Saved\n",Globals.SavedCount);
	printf("  %i Allocated\n",Globals.AllocatedCount);
	printf("  %i Processing\n",Globals.ProcessingCount);
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
