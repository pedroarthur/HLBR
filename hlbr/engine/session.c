#define DEBUG
// TODO: add a shutdown handler that frees all allocated memory for sessions
#include "session.h"
#include "hlbrlib.h"
#include "main_loop.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*+++++++++++++++++++Globals+++++++++++++++++*/
IPB*			Sessions[65536+1]; /**< All identified sessions. @see InitSession() */
int			TCPDecoderID;
int			IPDecoderID;
unsigned int		SessionCount = 0;
SFunc*			CreateFuncs;
SFunc*			DestroyFuncs;
extern	GlobalVars	Globals;

PP*			TimeHead;
PP*			TimeTail;

//#define DEBUG
//#define DEBUG_TIME
//#define DEBUG_DIRECTION	// Debug the find session direction/state code
#ifdef DEBUG_DIRECTION
#define DBGDIR(a)	a
#else
#define DBGDIR(a)
#endif


int RemountTCPStream(int, PP*, TCPData*);
int TCPStream_Unqueue(PP*);



/****************************************
* Add function that gets called whenever a
* session is created
*****************************************/
int AddSessionCreateHandler(void (*Func) (PP* Port, void* Data), void* Data){
	SFunc*	F;

	DEBUGPATH;

	if (!CreateFuncs){
		CreateFuncs=calloc(sizeof(SFunc),1);
		CreateFuncs->Func=Func;
		CreateFuncs->Data=Data;
		
		return TRUE;
	}

	F=CreateFuncs;
	while (F->Next) F=F->Next;
	
	F->Next=calloc(sizeof(SFunc),1);
	F=F->Next;
	F->Func=Func;
	F->Data=Data;
	
	return TRUE;
}

/****************************************
* Add function that gets called whenever a
* session is detroyed
*****************************************/
int AddSessionDestroyHandler(void (*Func) (PP* Port, void* Data), void* Data){
	SFunc*	F;
	
	DEBUGPATH;

	if (!DestroyFuncs){
		DestroyFuncs=calloc(sizeof(SFunc),1);
		DestroyFuncs->Func=Func;
		DestroyFuncs->Data=Data;
		
		return TRUE;
	}

	F=DestroyFuncs;
	while (F->Next) F=F->Next;
	
	F->Next=calloc(sizeof(SFunc),1);
	F=F->Next;
	F->Func=Func;
	F->Data=Data;
	
	return TRUE;
}

/**
 * Tell everyone a new session started.
 * Call the defined callback functions, alerting that a new TCP session was
 * created.
 */
void CallCreateFuncs(PP* Port)
{
	SFunc*	F;

	DEBUGPATH;

	F = CreateFuncs;
	
	while (F) {
		F->Func(Port, F->Data);
		F = F->Next;
	}
}

/***************************************
* Tell everyone a new session ended
***************************************/
void CallDestroyFuncs(PP* Port){
	SFunc*	F;

	DEBUGPATH;

	F=DestroyFuncs;
	
	while (F){
		F->Func(Port, F->Data);
		F=F->Next;
	}
}

/***************************************
* Find out what bin this goes in
***************************************/
unsigned short GetHash(unsigned int ip1, unsigned int ip2){
	unsigned short	hash;
	unsigned short	v1;
	
	DEBUGPATH;

	hash=ip1/65536;
	v1=(ip1 & 0x0000FFFF);
	hash ^= v1;
	v1=ip2/65536;
	hash ^= v1;
	v1=(ip2 & 0x0000FFFF);
	hash ^= v1;

	//return 100;
	return hash;
}

/************************************
* Find the IP Pair, if it doesn't 
* exist, create it
************************************/
IPP* FindIPPair(unsigned int IP1, unsigned int IP2)
{
	unsigned short	Hash;
	IPB*		Bin;
	IPP*		Pair;
	int		i;
	unsigned int	Top, Bottom, Middle;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("%s-",inet_ntoa(*(struct in_addr*)&IP1));
	printf("%s\n",inet_ntoa(*(struct in_addr*)&IP2));
#endif

	Hash=GetHash(IP1, IP2);

	if (!Sessions[Hash]){
#ifdef DEBUG
		printf("First IP Pair in this bin %u\n", Hash);
#endif	
		Sessions[Hash]=calloc(sizeof(IPB),1);
		if (!Sessions[Hash]){
			printf("Out of memory\n");
			return NULL;
		}
		
		Bin=Sessions[Hash];
		Bin->NumAllocated=IP_START;
		Bin->NumIPs=1;
		Bin->Pairs=calloc(sizeof(IPP*),IP_START+1);
		
		Bin->Pairs[0]=calloc(sizeof(IPP),1);
		Pair=Bin->Pairs[0];
		
		Pair->IP1=IP1;
		Pair->IP2=IP2;
		Pair->NumAllocated=0;
		Pair->NumPorts=0;
		Pair->RefuseFromThisIP = 0;
		Pair->Parent=Bin;
		
		return Pair;
	}
	
	/*replace this with a binary search after stable*/
	Bin = Sessions[Hash];
	
	Top = Bin->NumIPs-1;
	Bottom = 0;
	Middle = Bottom + ((Top-Bottom)/2);
	
	do {
		Pair=Bin->Pairs[Middle];
		
		if (!Pair) {
			printf("Pair was NULL. Tree corrupt\n");
			return NULL;
		}
		
		if ((Pair->IP1==IP1) && (Pair->IP2==IP2)) {
#ifdef DEBUG
			printf("Found Pair in Bin %i Slot %i\n",Hash, Middle);
#endif				
			return Pair;
		}
		
		if ( (IP1<Pair->IP1) || ( (IP1==Pair->IP1) && (IP2<Pair->IP2)) ) {
			if (Top == Bottom) break;
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		}else{
			if (Top == Bottom) break;
			
			Bottom = Middle+1;
			Middle = Bottom + ((Top-Bottom)/2);
		}
	} while (1);
	

#ifdef DEBUG
	printf("Creating new pair\n");
#endif
	
	if (Bin->NumIPs == Bin->NumAllocated) {
		/*Not found, create a new one*/
		Bin->Pairs=realloc(Bin->Pairs, sizeof(IPP*)*(Bin->NumAllocated+IP_GROW+2));
		if (!Bin->Pairs){
			printf("realloc failed\n");
			exit(1);
		}
	
		/*Null out the new pointers*/
		for (i = Bin->NumIPs; i < (Bin->NumAllocated+IP_GROW+1); i++) {
			Bin->Pairs[i]=NULL;
		}
	
		Bin->NumAllocated+=IP_GROW;
	}

	if ( (IP1>Pair->IP1) || ( (IP1==Pair->IP1) && (IP2>Pair->IP2)) )
		Middle++;
	
	memmove(&Bin->Pairs[Middle+1], &Bin->Pairs[Middle], sizeof(IPP*)*(Bin->NumIPs-Middle));
	
	Bin->Pairs[Middle]=calloc(sizeof(IPP),1);
	Pair=Bin->Pairs[Middle];
	Bin->NumIPs++;
	
	Pair->IP1=IP1;
	Pair->IP2=IP2;
	Pair->NumAllocated=0;
	Pair->NumPorts=0;
	Pair->RefuseFromThisIP = 0;
	Pair->Parent=Bin;
	
	return Pair;
}

/**
 * Add this session (port pair) to the "time list".
 * The "time list" is a linked list with the current sessions, meant to track
 * the time between the next packet in a session and the last one, to timeout
 * TCP sessions properly.
 * @see UpdateTime
 */
int AddToTime(PP* Port)
{
	DEBUGPATH;

	if (!TimeHead) {
		TimeHead = Port;
		TimeTail = Port;
		Port->TimeNext = NULL;
		Port->TimePrev = NULL;
		
		return TRUE;
	}
	
	if (!TimeTail) {
		PRINTERROR("TimeTail was NULL.  Time chain is corrupted!\n");
		return FALSE;
	}
	
	if (TimeTail->TimeNext) {
		PRINTERROR("TimeTail->Next was not NULL.  Time chain is corrupted!\n");
		return FALSE;
	}
	
	TimeTail->TimeNext = Port;
	Port->TimePrev = TimeTail;
	Port->TimeNext = NULL;
	TimeTail = Port;

	return TRUE;
}

/**
 * Update this session (port pair) when a new packet arrives.
 * Move this record to the end of the "time list". (no need to update the 
 * LastTime field since it should have been updated before calling this function)
 * The idea is: a new packet arrived, so start counting again the timeout for
 * this TCP session.
 */
int UpdateTime(PP* Port)
{
	DEBUGPATH;

	if (TimeTail == Port) {
		/* already the last */
		return TRUE;
	}

	if (TimeHead == Port) {
		if (Port->TimeNext == NULL) {
			/* only item in chain */
			return TRUE;
		}
		
		TimeHead = TimeHead->TimeNext;
		TimeHead->TimePrev = NULL;
		
		TimeTail->TimeNext = Port;
		Port->TimeNext = NULL;
		Port->TimePrev = TimeTail;
		TimeTail = Port;
		
		return TRUE;
	}
	
	Port->TimePrev->TimeNext = Port->TimeNext;
	Port->TimeNext->TimePrev = Port->TimePrev;
	Port->TimeNext = NULL;
	TimeTail->TimeNext = Port;
	Port->TimePrev = TimeTail;
	TimeTail = Port;
	
	return TRUE;
}


/**
 * Remove the TCP session (PortPair) from the bin.
 */
int RemovePort(PP* Port)
{
	IPP*		Pair;
	IPB*		Bin;
	int		Top, Bottom, Middle;
	unsigned short	Hash;
	
	DEBUGPATH;

#ifdef DEBUG_TIME
	printf("Freeing port with SessionID %u\n", Port->SessionID);
#endif

	/* tell everyone this is going away */
	CallDestroyFuncs(Port);

	/* logs session */
	if (Globals.logSession_StartEnd)
		printf("LE:%4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d dir:%d pcount:%d\n", 
		       Port->SessionID, IP_BYTES(Pair->IP1), Port->Port1,
		       IP_BYTES(Pair->IP2), Port->Port2,
		       Port->Direction, Port->TCPCount);

	/* get pointers to parents */
	Pair = Port->Parent;
	Bin = Pair->Parent;

	/* remove from the time linked list */
	if ( (Port == TimeHead) && (Port == TimeTail) ) {
		/* only item in the list */
		if (Port->TimeNext || Port->TimePrev) {
			PRINTERROR("Error Time chain is corrupt!\n");
			return FALSE;
		}
		
		TimeHead = NULL;
		TimeTail = NULL;
	} else if (Port == TimeHead) {
		Port->TimeNext->TimePrev = NULL;
		TimeHead = Port->TimeNext;
	} else if (Port == TimeTail) {
		Port->TimePrev->TimeNext = NULL;
		TimeTail = Port->TimePrev;
	} else {
		Port->TimePrev->TimeNext = Port->TimeNext;
		Port->TimeNext->TimePrev = Port->TimePrev;
	}
	Port->TimeNext = NULL;
	Port->TimePrev = NULL;

	/* find the entry in the ports list */
	Top = Pair->NumPorts-1;
	Bottom = 0;
	Middle = Bottom + ((Top-Bottom)/2);
	
	while (1) {	
		if (Pair->Ports[Middle] == Port) {
			break;
		}
		
		if ( (Port->Port1 < Pair->Ports[Middle]->Port1) || ( (Port->Port1 == Pair->Ports[Middle]->Port1) && (Port->Port2 < Pair->Ports[Middle]->Port2)) ){
			if (Top == Bottom) {
				PRINTERROR("Error: Port not found in parent\n");
				return FALSE;
			}
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom) {
				printf("Error: Port not found in parent\n");
				return FALSE;
			}
			
			Bottom = Middle + 1;
			Middle = Bottom + ((Top-Bottom)/2);
		}
	}
	
	/* remove this port from the ports list */
	memmove(&Pair->Ports[Middle], &Pair->Ports[Middle+1], sizeof(PP*)*(Pair->NumPorts - Middle - 1));
	Pair->NumPorts--;
	Pair->Ports[Pair->NumPorts] = NULL;
	FREE(Port->Stream0);
	FREE(Port->Stream1);
	free(Port);
	Port = NULL;
	
	/* if the pair is empty, remove it as well */
	if (Pair->NumPorts > 0) return TRUE;
	
	/* find this pair in the pairs list */
	Top = Bin->NumIPs - 1;
	Bottom = 0;
	Middle = Bottom + ((Top-Bottom)/2);
	
	while (1) {
		if (Bin->Pairs[Middle] == Pair) {
			break;
		}
		
		if ( (Pair->IP1 < Bin->Pairs[Middle]->IP1) || ( (Pair->IP1 == Bin->Pairs[Middle]->IP1) && (Pair->IP2 < Bin->Pairs[Middle]->IP2)) ) {
			if (Top == Bottom) {
				PRINTERROR("Error: Pair not found in parent\n");
				return FALSE;
			}
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom) {
				PRINTERROR("Error: Pair not found in parent\n");
				return FALSE;
			}
			
			Bottom = Middle + 1;
			Middle = Bottom + ((Top-Bottom)/2);
		}
	}
	
	/* remove this pair from the bin */
	memmove(&Bin->Pairs[Middle], &Bin->Pairs[Middle+1], sizeof(IPP*)*(Bin->NumIPs-Middle-1));
	Bin->NumIPs--;
	Bin->Pairs[Bin->NumIPs] = NULL;
	
	Hash = GetHash(Pair->IP1, Pair->IP2);
	
	free(Pair->Ports);
	Pair->Ports = NULL;
	free(Pair);
	Pair = NULL;	
	
	/* if the bin is empty, remove it */
	if (Bin->NumIPs>0) return TRUE;
	
	free(Bin->Pairs);
	Bin->Pairs = NULL;
	free(Sessions[Hash]);
	Sessions[Hash] = NULL;
	
	return TRUE;
}


/**
 * Find the Port Pair (TCP session), if it doesn't exist, create it.
 */
PP* FindPortPair(unsigned short Port1, unsigned short Port2, IPP* Pair, long int Now)
{
	int	i;
	PP*	Port;
	int	Top, Bottom, Middle;
	
	DEBUGPATH;

	if (!Pair->Ports) {
		DBG( PRINTERROR1("First Port Pair in this bin with sessionID %u\n", SessionCount) );
		Pair->Ports = calloc(sizeof(PP*), PORT_START+2);
		if (!Pair->Ports) {
			printf("Out of memory\n");
			return NULL;
		}
		
		Pair->NumAllocated = PORT_START;
		Pair->NumPorts = 1;
		Pair->Ports[0] = calloc(sizeof(PP), 1);
		
		Port = Pair->Ports[0];

		Port->Port1 = Port1;
		Port->Port2 = Port2;		
		Port->Parent = Pair;
		Port->LastTime = Now;
		Port->FirstTime = Now;
		if (Port->SessionID) {
			printf("SessionID was not 0\n");
		}
		Port->SessionID = SessionCount;
		Port->TheOtherPortPair = NULL;
		DBG( PRINTERROR1("Filling session %d's struct with 0s...\n", Port->SessionID) );
		bzero(&(Port->Seqs), sizeof(struct tcp_stream_buffer));
				
		SessionCount++;
		DBG( PRINT1("There are %i sessions\n", SessionCount) );
		AddToTime(Port);

		if (Globals.logSession_StartEnd || Globals.logSession_All)
			printf("LS:%4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d dir:%d pcount:%d\n", 
			       Port->SessionID, IP_BYTES(Pair->IP1), Port->Port1,
			       IP_BYTES(Pair->IP2), Port->Port2,
//		       (TData->Header->syn ? 's' : '.'),
//     		       (TData->Header->ack ? 'a' : '.'),
			       Port->Direction, Port->TCPCount);

		/* Tell everyone this session exists */
		CallCreateFuncs(Port);
		
		return Port;
	}
	
	/* Binary search for the port */
	Top = Pair->NumPorts-1;
	Bottom = 0;
	Middle = Bottom + ((Top-Bottom)/2);
	
	do {
		if (Middle>Pair->NumAllocated) {
			PRINTERROR("Tree is corrupted\n");
			exit(1);
		}
		
		Port = Pair->Ports[Middle];
		if (!Port) {
			PRINTERROR1("Error: Pointer was NULL Port %i\n", Middle);
			return NULL;
		}
		
		if ( (Port->Port1 == Port1) && (Port->Port2 == Port2) ) {
			DBG( PRINTERROR1("Found Port in Slot %i\n", Middle) );
			Port->LastTime = Now;
			UpdateTime(Port);
			return Port;
		}
		
		if ( (Port1 < Port->Port1) || ( (Port1 == Port->Port1) && (Port2 < Port->Port2) ) ) {
			if (Top == Bottom)
				break;
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom)
				break;
			
			Bottom = Middle + 1;
			Middle = Bottom + ((Top-Bottom)/2);
		}
	} while(1);
	
#ifdef DEBUG
	PRINTERROR1("Creating new port with sessionID %u\n", SessionCount);
#endif

	if (Pair->NumPorts == Pair->NumAllocated) {
		/* allocate some more ports */
		Pair->Ports = realloc(Pair->Ports, sizeof(PP*)*(Pair->NumAllocated+PORT_GROW+2));
		if (!Pair->Ports) {
			PRINTERROR("realloc failed\n");
			exit(1);
		}
	
		/* Null out the new pointers */
		for (i = Pair->NumPorts; i < (Pair->NumAllocated+PORT_GROW+1); i++) {
			Pair->Ports[i] = NULL;
		}
	
		Pair->NumAllocated += PORT_GROW;
	}
	
	if ((Port1 > Port->Port1) || ( (Port1 == Port->Port1) && (Port2 > Port->Port2) ) )
		Middle++;
	
	memmove(&Pair->Ports[Middle+1], &Pair->Ports[Middle], sizeof(PP*)*(Pair->NumPorts-Middle));
	
	Pair->Ports[Middle] = calloc(sizeof(PP),1);
	Port = Pair->Ports[Middle];
	Pair->NumPorts++;

	Port->Port1 = Port1;
	Port->Port2 = Port2;	
	Port->Parent = Pair;
	Port->LastTime = Now;
	Port->FirstTime = Now;
	if (Port->SessionID) {
		PRINTERROR("SessionID was not NULL\n");
	}
	Port->SessionID = SessionCount;
	Port->TheOtherPortPair = NULL;


	if (Globals.logSession_StartEnd)
		printf("LS:%4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d dir:%d pcount:%d\n", 
		       Port->SessionID,
#ifdef HLBR_LITTLE_ENDIAN
		       (Pair->IP1 & 0x000000ff), (Pair->IP1 & 0x0000ff00)>>8, (Pair->IP1 & 0x00ff0000)>>16, Pair->IP1>>24, Port->Port1,
		       (Pair->IP2 & 0x000000ff), (Pair->IP2 & 0x0000ff00)>>8, (Pair->IP2 & 0x00ff0000)>>16, Pair->IP2>>24, Port->Port2,
#else
		       Pair->IP1>>24, (Pair->IP1 & 0x00ff0000)>>16, (Pair->IP1 & 0x0000ff00)>>8, (Pair->IP1 & 0x000000ff), Port->Port1, 
		       Pair->IP2>>24, (Pair->IP2 & 0x00ff0000)>>16, (Pair->IP2 & 0x0000ff00)>>8, (Pair->IP2 & 0x000000ff), Port->Port2, 
#endif
//		       (TData->Header->syn ? 's' : '.'),
//     		       (TData->Header->ack ? 'a' : '.'),
		       Port->Direction, Port->TCPCount);

	AddToTime(Port);
	SessionCount++;
	DBG( PRINT1("There are %i sessions\n", SessionCount) );

	/* Tell everyone this session exists */
	CallCreateFuncs(Port);
	
	return Port;
}


/**
 * Free up the sessions (port pairs) that are expired.
 * Searches the "time list" and frees up sessions that timed out, i.e. sessions
 * where the time between a packet and the next one took longer than the 
 * set timeout for a TCP session.
 * @see AddToTime
 * @see UpdateTime
 */
int TimeoutSessions(long int Now)
{
	PP*	TimeNext;
	
	DEBUGPATH;

	while (TimeHead && (TimeHead->LastTime + SESSION_FORCE_TIMEOUT < Now)) {
		TimeNext = TimeHead->TimeNext;	
		RemovePort(TimeHead);
		TimeHead = TimeNext;
	}
	
/* Checks if there are pending sessions with just one packet waiting;
   this probably is the last packet in a TCP session, so let it go */
	while (TimeHead && (TimeHead->LastTime + (SESSION_FORCE_TIMEOUT/10) < Now)) {
		if (TimeHead->Stream0 != NULL) {
			if (TimeHead->Stream0->NumPieces == 1)
				TCPSessionUnblock(TimeHead->Stream0
		TimeNext = TimeHead->TimeNext;	
		RemovePort(TimeHead);
		TimeHead = TimeNext;
	}

	return TRUE;
}


/**
 * Find the session for this TCP packet.
 * This function is called for every TCP packet; it searches for its 
 * corresponding session, updates the state of both streams (cli->srv and
 * srv->cli), and remounts the payload of the packets of this same session,
 * to apply checks upon the remounted buffer.
 * @see FindIPPair()
 */
int AssignSessionTCP(int PacketSlot, void* Data)
{
	IPData*		IData;
	TCPData*	TData;
	unsigned int	IP1,IP2;
	unsigned short	Port1, Port2;
	IPP*		Pair;
	PP*		Port;
	Stream		struct tcp_stream;
	char		remount = 0;	// try to remount this packet?
	char		outoforder = 0;	// packet isn't in the expected order?

	DEBUGPATH;

	GetDataByID(PacketSlot, IPDecoderID, (void**)&IData);
	if (!IData) {
		PRINTPKTERROR(PacketSlot, IData, NULL, FALSE);
		PRINTERROR("This was supposed to be a TCP packet\n");
		return FALSE;
	}

	TData = (TCPData*)Data;
	if (!TData) {
		PRINTPKTERROR(PacketSlot, IData, TData, FALSE);
		PRINTERROR("TCP Data was NULL\n");
		return FALSE;
	}

	// Assigns IP1 & IP2: IP1 is the lesser of the src & dst IPs
	if (IData->Header->saddr < IData->Header->daddr) {
		IP1 = IData->Header->saddr;
		IP2 = IData->Header->daddr;
		Port1 = ntohs(TData->Header->source);
		Port2 = ntohs(TData->Header->dest);
	} else {
		IP1 = IData->Header->daddr;
		IP2 = IData->Header->saddr;
		Port1 = ntohs(TData->Header->dest);
		Port2 = ntohs(TData->Header->source);
	}

	/* Finds a pair of IPs in the IP Pair Bin */
	Pair = FindIPPair(IP1, IP2);
	if (!Pair) {
		PRINTPKTERROR(PacketSlot, IData, TData, FALSE);
		PRINTERROR("Failed to assign session pair for %d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d\n",
			   IP_BYTES(IP1), Port1, IP_BYTES(IP2), Port2);
		return FALSE;
	}
	/* Finds a session (a pair of ports in the pair of IPs) in the Bin */
	Port = FindPortPair(Port1, Port2, Pair, Globals.Packets[PacketSlot].tv.tv_sec);
	if (!Port) {
		PRINTPKTERROR(PacketSlot, IData, TData, FALSE);
		PRINTSESERROR(Port, FALSE);
		PRINTERROR("Failed to assign session port for %d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d\n",
			   IP_BYTES(IP1), Port1, IP_BYTES(IP2), Port2);
		return FALSE;
	}

	/* Discover the direction and state of this session */

	if ( (Port->ServerState == TCP_STATE_NEW) && (Port->ClientState == TCP_STATE_NEW) ) {
		/* We don't know what direction or state this is yet.
		 *
		 * If it starts with a SYN:
		 *   Sender is Client, State is SYN
		 * If it starts with a SYN|ACK:
		 *   Sender is Server, State is SYN|ACK
		 * If it starts with a FIN:
		 *   Sender is Client, State is DATA, FIN Set for Client
		 * If it starts with a RST:
		 *   Sender is Server, State is RESET
		 * If it starts with a normal ACK:
		 *   Sender is Client, State is DATA
		 */
		
		if (TData->Header->syn && !(TData->Header->ack || TData->Header->fin || TData->Header->rst) ) {
			DBGDIR( printf("Started with a SYN\n") );

			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP2_SERVER;
			} else {
				Port->Direction = SESSION_IP1_SERVER;
			}
			
			Port->ClientState = TCP_STATE_SYN;
			Port->ClientSeq = ntohl(TData->Header->seq);
			Port->ClientAck = ntohl(TData->Header->ack_seq);
		} else if (TData->Header->syn && TData->Header->ack && !(TData->Header->fin || TData->Header->rst) ) {
			DBGDIR( printf("Started with a SYN|ACK\n") );

			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP1_SERVER;
			} else {
				Port->Direction = SESSION_IP2_SERVER;
			}
			
			Port->ServerState = TCP_STATE_SYNACK;
			Port->ServerSeq = ntohl(TData->Header->seq);
			Port->ServerAck = ntohl(TData->Header->ack_seq);
		} else if (TData->Header->rst) {
			DBGDIR( printf("Started with a RST\n") );

			if (IP1 == IData->Header->saddr){
				Port->Direction = SESSION_IP1_SERVER;
			}else{
				Port->Direction = SESSION_IP2_SERVER;
			}
			
			Port->ServerState = TCP_STATE_RESET;
			Port->ServerSeq = ntohl(TData->Header->seq);
			Port->ServerAck = ntohl(TData->Header->ack_seq);
		} else if (TData->Header->fin) {
			DBGDIR( printf("Started with a FIN\n") );

			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP2_SERVER;
			} else {
				Port->Direction = SESSION_IP1_SERVER;
			}
			
			Port->ClientState = TCP_STATE_DATA;
			Port->ClientSeq = ntohl(TData->Header->seq);
			Port->ClientAck = ntohl(TData->Header->ack_seq);
		} else {
			/* This would happen only when HLBR is started when 
			   there are already active TCP sessions ? */

			DBGDIR( PRINT("Startup in the middle of a session\n") );

			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP2_SERVER;
			}else{
				Port->Direction = SESSION_IP1_SERVER;
			}
			
			Port->ClientState = TCP_STATE_DATA;
			Port->ServerState = TCP_STATE_DATA;
			Port->ClientSeq = ntohl(TData->Header->seq);
			Port->ClientAck = ntohl(TData->Header->ack_seq);
			/* It's useless to try to remount anything if we're not
			   catching the initial data */
			Port->noremount = 1;
		}

	} else {
		/* We already had a state for this session. Let's just see
		   if it changed. */

		/* see if this came from the client or the server */
		if (
			((Port->Direction == SESSION_IP1_SERVER) && (IData->Header->saddr == IP1)) ||
			((Port->Direction == SESSION_IP2_SERVER) && (IData->Header->saddr == IP2))
			) {
			
			DBG( PRINT("This packet came from the server\n") );
			
			if ( (Port->ClientState == TCP_STATE_FIN) && (Port->ServerState == TCP_STATE_FIN) && !(TData->Header->fin || TData->Header->syn || TData->Header->rst) ) {
				DBGDIR( PRINT("Final ACK\n") );

				if ( (Port->ClientSeq + 1) != ntohl(TData->Header->ack_seq)) {
					//printf("Seq didn't match (final ACK after FIN from client)\n");
				}
				Port->ClientState = TCP_STATE_LATE;
				Port->ServerState = TCP_STATE_LATE;
			} else if (TData->Header->syn && TData->Header->ack  && !(TData->Header->rst || TData->Header->fin) ) {

				/* syn|ack from the server */

				if ( (Port->ServerState == TCP_STATE_NEW) && (Port->ClientState == TCP_STATE_SYN)) {
					DBG( PRINT("Normal SYN|ACK\n") );

					Port->ServerState = TCP_STATE_SYNACK;
					Port->ServerSeq = ntohl(TData->Header->seq);
					Port->ServerAck = ntohl(TData->Header->ack_seq);
					
					if (Port->ServerAck != (Port->ClientSeq+1) ){
						DBG( PRINT("SYN|ACK didn't match\n") );
						Port->Error = TRUE;
					}
				} else if (Port->ServerState == TCP_STATE_SYNACK) {
					DBGDIR( PRINT("Resend of the SYN|ACK\n") );
					if ( (Port->ServerSeq != ntohl(TData->Header->seq)) || (Port->ServerAck != ntohl(TData->Header->ack_seq)) ) {
						DBG( PRINT("Reset SYN|ACK didn't match original\n") );
						Port->Error = TRUE;
					}
				}
			} else if (TData->Header->rst) {
				DBGDIR( PRINT("Server sent a RESET\n") );

				Port->ServerState = TCP_STATE_RESET;
				Port->ServerSeq = ntohl(TData->Header->seq);
				Port->ServerAck = ntohl(TData->Header->ack_seq);
			} else if (TData->Header->fin) {
				DBGDIR( printf("Server sent a FIN\n") );

				Port->ServerState=TCP_STATE_FIN;
				Port->ServerSeq=ntohl(TData->Header->seq);
				Port->ServerAck=ntohl(TData->Header->ack_seq);
				Port->ServerFin=1;
			} else {
				if ( (Port->ServerState == TCP_STATE_SYNACK) && (Port->ClientState = TCP_STATE_DATA) ){
					DBGDIR( PRINT("First Data packet from server\n") );

					Port->ServerState = TCP_STATE_DATA;
					Port->ServerSeq = ntohl(TData->Header->seq);
					Port->ServerAck = ntohl(TData->Header->ack_seq);
					remount = 1;
				} else if (Port->ServerState == TCP_STATE_DATA) {
					DBGDIR( printf("Normal Data from Server\n") );

					Port->ServerSeq = ntohl(TData->Header->seq);
					Port->ServerAck = ntohl(TData->Header->ack_seq);
				} else {
					DBGDIR( PRINT("Error: This packet was unexpected (1)\n");
					Port->Error = TRUE;
				}
			}
		} else {

			DBG( PRINT("This packet came from the client\n") );
			
			if ( (Port->ClientState == TCP_STATE_FIN) && (Port->ServerState == TCP_STATE_FIN) && !(TData->Header->fin || TData->Header->syn || TData->Header->rst) ) {
				DBGDIR( PRINT("Final ACK\n") );

				if ( (Port->ServerSeq+1) != ntohl(TData->Header->ack_seq)) {
					//printf("Seq didn't match (final ACK after FIN from server)\n");
				}
				Port->ClientState = TCP_STATE_LATE;
				Port->ServerState = TCP_STATE_LATE;
			} else if (!(TData->Header->fin || TData->Header->rst) ) {
				if ( (Port->ClientState == TCP_STATE_SYN) && (Port->ServerState == TCP_STATE_SYNACK) ){
					/* Acking the SYN|ACK */
					DBGDIR( PRINT("Normal SYN|ACK ACK\n") );

					Port->ClientState = TCP_STATE_DATA;
					Port->ClientSeq = ntohl(TData->Header->seq);
					Port->ClientAck = ntohl(TData->Header->ack_seq);
					if (TData->Header->DataLen > 0) {
						DBG( PRINT("syn|ack ack has payload?\n") );
						remount = 1;
					}
				} else if (Port->ClientState == TCP_STATE_DATA) {
					DBGDIR( PRINT("Normal Client Traffic\n") );

					Port->ClientSeq = ntohl(TData->Header->seq);
					Port->ClientAck = ntohl(TData->Header->ack_seq);
					remount = 1;
				} else {
					DBGDIR( PRINT("Error:  This packet was unexpected (2)\n") );
				}
			} else if (TData->Header->rst) {
				DBGDIR( PRINT("Client sent a RST\n") );

				Port->ClientState = TCP_STATE_RESET;
			}else if (TData->Header->fin) {
				DBGDIR( PRINT("Client sent a FIN\n") );

				Port->ClientState = TCP_STATE_FIN;
			} else {
				DBGDIR( PRINT("Error:  This packet was unexpected (3)\n") );
			}
		}
	}


	//RemountTCPStream(PacketSlot, Port, TData);
		
	/* update stats and pointers */
	Port->TCPCount++;
	Globals.Packets[PacketSlot].Stream = Port;


	/* Does the magic - remounts the payload in the big buffer 
	   & call tests upon it */

	if (remount && !(Port->noremount)) {
		if ((Port->Direction == SESSION_IP1_SERVER && TData->Header->saddr == IP2) ||
		    (Port->Direction == SESSION_IP2_SERVER && TData->Header->saddr == IP1)) {
			if (Port->Stream0 == NULL) {
				Port->Stream0 = MALLOC(sizeof(struct tcp_stream));
				bzero(Port->Stream0, sizeof(struct tcp_stream));
			}
			Stream = Port->Stream0;
		} else {
			if (Port->Stream1 == NULL) {
				Port->Stream1 = MALLOC(sizeof(struct tcp_stream));
				bzero(Port->Stream1, sizeof(struct tcp_stream));
			}
			Stream = Port->Stream1;
		}

		
	}

	

	TimeoutSessions(Globals.Packets[PacketSlot].tv.tv_sec);

	return TRUE;
}

/**
 * Sets up the session handler.
 * Global variable IPB holds info about all identified sessions.
 * @see ip_bin
 * @see ip_pair
 * @see port_pair
 */
int InitSession()
{
	DEBUGPATH;

	bzero(Sessions, sizeof(IPB*)*65536);
	TimeHead = NULL;
	CreateFuncs = NULL;
	DestroyFuncs = NULL;

	IPDecoderID = GetDecoderByName("IP");
	TCPDecoderID = GetDecoderByName("TCP");

	return TRUE;
}



/**
 * Remounts packets in a TCP stream and check them together for signatures.
 * @return FALSE if the packet couldn't be queued due to lack of space
 * @see tcp_stream_buffer
 */
int RemountTCPStream(int PacketSlot, PP* Port, TCPData* TData)
{
//	TCPData*	TData = 0;
	int		i;

	DEBUGPATH;
	DBG( PRINT4("RemountTCPStream: Session:%d TCPCount:%d [%d,%d]\n",
			Port->SessionID, Port->TCPCount,
			TData->Header->seq, TData->Header->ack_seq) );
#ifdef DEBUG000
	// dumping contents of this session's buffers...
	PRINTERROR3("	--- TCP stream buffer ---\n	%d pieces, TopSeq: %d, LastSeq: %d\n",
		    Port->Seqs.num_pieces, Port->Seqs.TopSeq, Port->Seqs.LastSeq);
	for (i = 0; i < Port->Seqs.num_pieces; i++)
		PRINTERROR4("	[%d] %d -> %d		PacketSlot:%d\n",
			   i, Port->Seqs.pieces[i].piece_start,
			   Port->Seqs.pieces[i].piece_end,
			   Port->Seqs.pieces[i].PacketSlot);
#endif	/* DEBUG */
	
	if (Port->Seqs.num_pieces == TCP_QUEUE_SIZE)
		return FALSE;

	/*if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)) {
 		PrintPacketSummary(stderr, PacketSlot, NULL, TData, FALSE);
		PRINTERROR("This was supposed to be a TCP packet\n");
		return FALSE;
		}*/

	// packets with no payload aren't queued
	if (TData->DataLen == 0)
		return TRUE;

	// this is the very first packet of this session
	if (Port->Seqs.LastSeq == 0 && Port->Seqs.TopSeq == 0) {
		DBG( PRINTERROR2("Very first packet of session %d with payload (# of packets: %d)\n", Port->SessionID, Port->TCPCount) );
		Port->Seqs.TopSeq = TData->Header->seq - 1;
		Port->Seqs.LastSeq = TData->Header->seq - 1;
	}

	// new packet fits right after first bunch of packets in buffer
	if (TData->Header->seq == Port->Seqs.LastSeq + 1) {
		if (Globals.logSession_All)
			PRINT2("Session %d: packet %d fits right at buffer's end\n", Port->SessionID, PacketSlot);

		if (Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1 >= TCP_CACHE_SIZE) {
			PRINTPKTERROR(-1, NULL, TData, FALSE);
			PRINTSESERROR(Port, FALSE);
			PRINTERROR("out of space in TCP cache\n");
			return FALSE;
		}
		memcpy(TData->Data, 
		       &(Port->Seqs.buffer) + (Port->Seqs.LastSeq - Port->Seqs.TopSeq), 
		       TData->DataLen);

		// finds position for the packet in pieces[]
		for (i = 0; Port->Seqs.pieces[i].piece_end < Port->Seqs.LastSeq && i < TCP_QUEUE_SIZE; i++);
		if (i == TCP_QUEUE_SIZE) {
			PRINTERROR("pieces[] out of space?\n");
			return FALSE;
		}
		DBG( PRINTERROR1("\tUsing pieces[%d]...", i) );

		// move other pieces[] forward, to make space
		if (i < TCP_QUEUE_SIZE - 1) {
			DBG( PRINTERROR("\n\tNeed to move other pieces[] forward, to make space\n") );
			memmove(&(Port->Seqs.pieces[i+1]), &(Port->Seqs.pieces[i]), 
				sizeof(struct tcp_stream_piece)*(TCP_QUEUE_SIZE-i));
		}
		Port->Seqs.pieces[i].piece_start = TData->Header->seq;
		Port->Seqs.pieces[i].piece_end = TData->Header->seq + TData->DataLen-1;
		Port->Seqs.pieces[i].PacketSlot = PacketSlot;
		Port->Seqs.num_pieces++;
		Port->Seqs.LastSeq = TData->Header->seq + TData->DataLen - 1;
		DBG( PRINTERROR6(" Used: %d->%d, ps:%d, num_pieces:%d, Top/Last:%d/%d\n",
				Port->Seqs.pieces[i].piece_start,
				Port->Seqs.pieces[i].piece_end,
				Port->Seqs.pieces[i].PacketSlot,
				Port->Seqs.num_pieces,
				Port->Seqs.TopSeq, Port->Seqs.LastSeq) );

		// try to add queued packets to the buffer
		// try multiple times, because after a packet is popped out,
		// maybe there's room for another one
		while (TCPStream_Unqueue(Port));
	} else {
		// This packet doesn't follow the previous one. So we queue it
		if (Globals.logSession_All)
			PRINT2("Session %d: packet %d doesn't fits at buffer's end, queuing it\n", Port->SessionID, PacketSlot);

		DBG( PRINTPKTERROR(-1, NULL, TData, FALSE) );
		DBG( PRINTSESERROR(Port, FALSE) );
		DBG( PRINTERROR2("packet doesn't follows previous one (LastSeq:%d this packet's seq:%d)\n", Port->Seqs.LastSeq, TData->Header->seq) );
		if (Port->Seqs.queue_size < TCP_QUEUE_SIZE) 
			Port->Seqs.queue[i++] = PacketSlot;
		BlockPacket(PacketSlot);
	}

	return TRUE;
}

/**
 * Try to add to the TCP buffer packets previously queued.
 * @return TRUE if a packet is unqueued
 */
int TCPStream_Unqueue(PP* Port)
{
	TCPData*	TData;
	int i;

	DEBUGPATH;

	// Nothing to unqueue
	if (!Port->Seqs.queue_size)
		return FALSE;

	// Even if there's something to unqueue, pieces[] can't hold it
	if (Port->Seqs.queue_size == TCP_QUEUE_SIZE)
		return FALSE;

	for (i = 0; i < Port->Seqs.queue_size; i++) {
		GetDataByID(Port->Seqs.queue[i], TCPDecoderID, (void**)&TData);
		if (!TData) {
			PrintPacketSummary(stderr, Port->Seqs.queue[i], NULL, TData, FALSE);
			PRINTERROR("This was supposed to be a TCP packet\n");
			return FALSE;
		}

		// put this piece after the others
		if (TData->Header->seq == Port->Seqs.LastSeq + 1) {
			if (TData->DataLen > (TCP_CACHE_SIZE - Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1))
				// buffer can't hold the packet!
				// then just wait for another time...
				return FALSE;

			memcpy(&(Port->Seqs.buffer) + Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1,
			       TData->Data, TData->DataLen);

			// add to pieces (at the end)
			Port->Seqs.pieces[Port->Seqs.num_pieces].piece_start = TData->Header->seq;
			Port->Seqs.pieces[Port->Seqs.num_pieces].piece_end = TData->Header->seq + TData->DataLen - 1;
			Port->Seqs.pieces[Port->Seqs.num_pieces].PacketSlot = Port->Seqs.queue[i];

			// unqueue it (moving subsequent records up)
			if (Port->Seqs.queue_size == TCP_QUEUE_SIZE)
				Port->Seqs.queue_size--;
			else
				memmove(&(Port->Seqs.queue[i]), 
					&(Port->Seqs.queue[i+1]),
					(Port->Seqs.queue_size-- - i - 1) * sizeof(int));

			return TRUE;
			
		// put this piece before the others
		} else if (TData->Header->seq + TData->DataLen - 1 ==
			   Port->Seqs.TopSeq) {
			if (TData->DataLen > (TCP_CACHE_SIZE - Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1))
				// buffer can't hold the packet!
				// then just wait for another time...
				return FALSE;

			// first, move down the buffer to make space...
			memmove(&(Port->Seqs.buffer) + TData->DataLen,
				&(Port->Seqs.buffer),
				Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1);
			// ...then insert data at beginning of buffer
			memcpy(&(Port->Seqs.buffer), TData->Data, TData->DataLen);

			// add to pieces (at the beginning)
			memmove(&(Port->Seqs.pieces[1]), &(Port->Seqs.pieces[0]),
				(Port->Seqs.num_pieces - 1) * sizeof(struct tcp_stream_buffer));
			Port->Seqs.num_pieces++;

			// unqueue it (moving subsequent records up)
			if (Port->Seqs.queue_size == TCP_QUEUE_SIZE)
				Port->Seqs.queue_size--;
			else
				memmove(&(Port->Seqs.queue[i]), 
					&(Port->Seqs.queue[i+1]),
					(Port->Seqs.queue_size-- - i - 1) * sizeof(int));

			return TRUE;
		} else if (
			((TData->Header->seq < Port->Seqs.LastSeq) &&
			 (TData->Header->seq > Port->Seqs.TopSeq)) ||
			((Port->Seqs.TopSeq > TData->Header->seq) &&
			 (Port->Seqs.TopSeq < TData->Header->seq + TData->DataLen - 1)) ) {
			// packet boundaries overwrite! drop the packet
			// (taken from action_drop.c)
			Globals.Packets[Port->Seqs.queue[i]].PassRawPacket = FALSE;
			if (Globals.Packets[Port->Seqs.queue[i]].Status == PACKET_STATUS_BLOCKED)
				TCPRemount_unblock(Port->Seqs.queue[i], TRUE);
			return FALSE; // should really continue trying other packets in queue, but array can change after calling TCPStream_unblock
		}
	}

	return FALSE;
}

/** Unblock the first packet in the TCP stream buffer this packet belongs.
 * The very first packet of the TCP stream buffer will be marked as PENDING,
 * so that it can be routed at the next opportunity.
 * If thispacket is TRUE, that means this very packet is being dropped 
 * (by an action), and so, if this isn't the very first packet of the buffer,
 * then after unblocking the first one, get the tcp_piece struct of this very
 * packet and change the pointer to the packet to NULL. So when it's time to
 * unblock the corresponding piece we don't need to really unblock the packet
 * because it went away already.
 * @return FALSE if anything unexpected occured (such as null pointers)
 */
int TCPRemount_unblock(int PacketSlot, int thispacket)
{
	PacketRec*			p;
	struct tcp_stream_buffer*	seq;
	int				nseq;
	signed char			i, piece;
	int				up;
	TCPData*			TData;

	DEBUGPATH;

	p = &Globals.Packets[PacketSlot];
	up = PacketSlot;
	
	if (!(p->Stream)) {
		DBG( PRINTERROR1("Packet %d's Stream pointer is null!\n", PacketSlot) );
		return FALSE;
	}
	seq = &(p->Stream->Seqs);
	if (seq->num_pieces == 0) {
		DBG( PRINTERROR1("Packet %d's stream doesn't have any pieces to be unblocked\n", PacketSlot) );
		return FALSE;
	}
	/* if there's only one piece in the buffer, it can be unblocked only
	   if it's the last packet in the TCP session */
	if (seq->num_pieces == 1) {
		GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData);
		if (TData)
			if (!TData->Header->fin && !TData->Header->rst) {
				DBG( PRINTERROR1("TCP buffer for packet %d has only one packet and it isn't a FIN or RST one\n", PacketSlot) );
				return FALSE;
			}
	}
	
	nseq = seq->pieces[0].piece_start + 1;
	piece = -1;
	for (i = 0; i < seq->num_pieces; i++)
		if (seq->pieces[i].piece_start < nseq) {
			nseq = seq->pieces[i].piece_start;
			piece = i;
		}
	if (piece > -1) {
		up = seq->pieces[piece].PacketSlot;
		// if this piece's PacketSlot is valid, finally route this poor packet
		if (seq->pieces[piece].PacketSlot > -1) {
			Globals.Packets[seq->pieces[piece].PacketSlot].Status = PACKET_STATUS_IDLE;
			RouteAndSend(seq->pieces[piece].PacketSlot);
			ReturnEmptyPacket(seq->pieces[piece].PacketSlot);
		}
		// remove piece from pieces array
		if (piece < TCP_QUEUE_SIZE)
			memmove(&(seq->pieces[piece]), 
				&(seq->pieces[piece+1]),
				(seq->num_pieces - piece - 1) * sizeof(struct tcp_stream_piece));
		seq->num_pieces--;
	}

	if ((thispacket) && (PacketSlot != up)) {
		for (i = 0; i < seq->num_pieces; i++)
			if (seq->pieces[i].PacketSlot == PacketSlot)
				seq->pieces[i].PacketSlot = -1;
	}

	return TRUE;
}
