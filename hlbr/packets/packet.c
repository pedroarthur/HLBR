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

pthread_mutex_t		PacketMutex;
int					PacketLockID=0;
unsigned int 		CurPacketNum=0;

//#define DEBUG
//#define DEBUGPACKETS
//#define DEBUGLOCKS

/**************************************
* Given the name of a packet type,
* return its ID
**************************************/
int GetPacketTypeByName(char* Name){

#ifdef DEBUGPATH
	printf("In GetPacketTypeByName\n");
#endif

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

#ifdef DEBUGPATH
	printf("In GetPacketProtoByName\n");
#endif

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

#ifdef DEBUGPATH
	printf("In GetPacketProtoByName\n");
#endif

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

#ifdef DEBUGPATH
	printf("In OpenInterface\n");
#endif

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
int OpenInterfaces()
{
	int 	i;

#ifdef DEBUGPATH
	printf("In OpenInterfaces\n");
#endif

	for (i=0;i<Globals.NumInterfaces;i++)
		if (!OpenInterface(i)) return FALSE;
		
	return TRUE;
}

/******************************************
* Read packet(s) from an interface
* Packets will be put on the pending queue
******************************************/
int ReadPacket(int InterfaceID)
{
	InterfaceRec*	Interface;

#ifdef DEBUGPATH
	printf("In ReadPacket\n");
#endif

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
int WritePacket(int PacketSlot)
{
	InterfaceRec*	Interface;
	int				i;
	int				InterfaceID;
	unsigned char*	Packet;
	int				PacketLen;

#ifdef DEBUGPATH
	printf("In WritePacket\n");
#endif

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

/**
 * Marks a packet as 'pending' (thread safe, called from ReadPacket)
 * Gets called every time a packet gets put on the pending list. Uses a 
 * mutex lock (to avoid problems with threads).
 * This may be called more than once per ReadPacket request.
 * @see ReadPacket
 */
int AddPacketToPending(int PacketSlot)
{
#ifdef DEBUGPATH
	printf("In AddPacketToPending\n");
#endif

	hlbr_mutex_lock(&PacketMutex, ADD_PACKET_1, &PacketLockID);
	
	Globals.Packets[PacketSlot].Status=PACKET_STATUS_PENDING;
	LastPendingSlot=PacketSlot;
	Globals.PendingCount++;
	Globals.AllocatedCount--;
	
	hlbr_mutex_unlock(&PacketMutex);

	return TRUE;
}

#ifdef TCP_STREAM

/**
 * Marks a packet as 'blocked' (thread safe)
 * Blocked packets can't be processed until are unblocked. Usually they're
 * blocked by session handling functions
 * @see RemountTCPStream
 */
int BlockPacket(int PacketSlot)
{
	hlbr_mutex_lock(&PacketMutex, ADD_PACKET_1, &PacketLockID);
	Globals.Packets[PacketSlot].Status=PACKET_STATUS_BLOCKED;
	hlbr_mutex_unlock(&PacketMutex);

	return TRUE;
}

#endif	// TCP_STREAM

/**
 * Pops a packet off the pending queue
 * Give the caller a packet off the pending queue (marked as 
 * PACKET_STATUS_PENDING
 */
int PopFromPending()
{
	int		PacketSlot;
	int		i;
#ifdef DEBUGPATH
	printf("In PopFromPending\n");
#endif
	
	PacketSlot=PACKET_NONE;
	hlbr_mutex_lock(&PacketMutex, POP_PACKET_1, &PacketLockID);
	
	for (i=0;i<MAX_PACKETS;i++){
		if (Globals.Packets[i].Status==PACKET_STATUS_PENDING){
			Globals.Packets[i].Status=PACKET_STATUS_PROCESSING;
			hlbr_mutex_unlock(&PacketMutex);
			Globals.PendingCount--;
			Globals.ProcessingCount++;
			return i;
		}
	}
	
	hlbr_mutex_unlock(&PacketMutex);
	
	return PACKET_NONE;
}

/*******************************************
* Get a packet from the pool
********************************************/
int GetEmptyPacket(){
	PacketRec*	Packet;
	int			i;
#ifdef DEBUGPATH
	printf("In GetEmptyPacket\n");
#endif	

	hlbr_mutex_lock(&PacketMutex, GET_PACKET_1, &PacketLockID);

	Packet=NULL;
	for (i=LastFreeSlot; i<MAX_PACKETS;i++){
		if (Globals.Packets[i].Status==PACKET_STATUS_IDLE){
#ifdef DEBUG
			printf("Found IDLE packet in slot %i\n",i);
#endif		
			Globals.Packets[i].SaveCount=0;
			Globals.Packets[i].Status=PACKET_STATUS_ALLOCATED;
			Packet=&Globals.Packets[i];
			Packet->PacketSlot=i;
			break;
		}
	}

	if (!Packet)	
	for (i=0; i<LastFreeSlot;i++){
		if (Globals.Packets[i].Status==PACKET_STATUS_IDLE){
#ifdef DEBUG
			printf("Found IDLE packet in slot %i\n",i);
#endif		
			Globals.Packets[i].SaveCount=0;
			Globals.Packets[i].Status=PACKET_STATUS_PENDING;
			Packet=&Globals.Packets[i];
			Packet->PacketSlot=i;
			break;
		}
	}

	if (!Packet){
#ifdef DEBUG
		printf("There were no free packets\n");
#endif	
		hlbr_mutex_unlock(&PacketMutex);
		return PACKET_NONE;
	}
	
	/*initialize the packet*/
	Packet->PacketLen=0;
	memset(Packet->RuleBits, 0xFF, MAX_RULES/8);
	Packet->tv.tv_sec=0;
	Packet->tv.tv_usec=0;
	Packet->NumDecoderData=0;
	Packet->PassRawPacket=TRUE;
	Packet->PacketNum=CurPacketNum++;
	Packet->PacketSlot=i;
	Packet->RawPacket=Packet->TypicalPacket;
	Packet->LargePacket=FALSE;
	
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
	
#ifdef DEBUGPATH
	printf("In ReturnEmptyPacket\n");
#endif	

	hlbr_mutex_lock(&PacketMutex, RETURN_PACKET_1, &PacketLockID);
	
	if (Globals.Packets[PacketSlot].SaveCount<1){
		p=&Globals.Packets[PacketSlot];
	
		if  (p->LargePacket){
			free(p->RawPacket);
			p->RawPacket=p->TypicalPacket;
			p->LargePacket=FALSE;
		}
	
		for (i=0;i<p->NumDecoderData;i++){
			if (p->DecoderInfo[i].Data) free(p->DecoderInfo[i].Data);
			p->DecoderInfo[i].Data=NULL;
		}
		
		switch(Globals.Packets[PacketSlot].Status){
		case PACKET_STATUS_ALLOCATED:
			Globals.AllocatedCount--;
			break;
		case PACKET_STATUS_PROCESSING:
			Globals.ProcessingCount--;
			break;
		}
		Globals.IdleCount++;
		Globals.Packets[PacketSlot].Status=PACKET_STATUS_IDLE;		
	}else{
		Globals.Packets[PacketSlot].Status=PACKET_STATUS_SAVED;
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

/************************************
* Start a new dedicated thread to
* read the interface
************************************/
int StartInterfaceThread(int InterfaceID){
	InterfaceRec*	Interface;
#ifdef DEBUGPATH
	printf("In StartIntefaceThread\n");
#endif

#ifndef HAS_THREADS
	return FALSE;
#else
	Interface=&Globals.Interfaces[InterfaceID];
	
	switch(Interface->Type){
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
#ifdef DEBUGPATH
	printf("in RuleIsActive\n");
#endif	

	return GetBit(Globals.Packets[PacketSlot].RuleBits, Globals.NumRules, RuleNum);	
}

/**********************************************
* Mark a rule as no longer active
**********************************************/
inline int SetRuleInactive(int PacketSlot, int RuleNum){
#ifdef DEBUGPATH
	printf("In SetRuleInactive\n");
#endif	
	
	SetBit(Globals.Packets[PacketSlot].RuleBits, Globals.NumRules, RuleNum, 0);
	
	return TRUE;
}

/**********************************************
* Given a name, return the interface ID
**********************************************/
int GetInterfaceByName(char* Name){
	int	i;

#ifdef DEBUGPATH
	printf("GetInterfaceByName\n");
#endif

	for (i=0;i<Globals.NumInterfaces;i++){
		if (strcasecmp(Name, Globals.Interfaces[i].Name)==0){
			return i;
		}
	}

	return INTERFACE_NONE;
}
