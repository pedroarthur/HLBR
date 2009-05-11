#define DEBUG
//#define DEBUG_TIME	// Debug the session timing out code
//#define DEBUG_DIRECTION	// Debug the find session direction/state code

// TODO: add a shutdown handler that frees all allocated memory for sessions (when program exits)

#include "session.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#ifdef TCP_STREAM_REASSEMBLY
#include "../packets/packet.h"
#endif

// Globals
IPB*				Sessions[65536+1];
int					TCPDecoderID;
int					IPDecoderID;
unsigned int		SessionCount = 0;
SFunc*				CreateFuncs;
SFunc*				DestroyFuncs;
extern	GlobalVars	Globals;

PP*					TimeHead;
PP*					TimeTail;

//#define DEBUG
//#define DEBUG_TIME
//#define DEBUG_DIRECTION

/**
 * Add a callback function that gets called whenever a TCP session is created.
 * @see CallCreateFuncs
 */
int AddSessionCreateHandler(void (*Func) (PP* Port, void* Data), void* Data) {
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

/**
 * Add a callback function that gets called whenever a TCP session is detroyed.
 */
int AddSessionDestroyHandler(void (*Func) (PP* Port, void* Data), void* Data) {
	SFunc*  F;
        
	DEBUGPATH;

	if (!DestroyFuncs){
		DestroyFuncs = calloc(sizeof(SFunc),1);
		DestroyFuncs->Func = Func;
		DestroyFuncs->Data = Data;
        
		return TRUE;
	}

	F = DestroyFuncs;
	while (F->Next) 
		F = F->Next;
        
	F->Next = calloc(sizeof(SFunc),1);
	F = F->Next;
	F->Func = Func;
	F->Data = Data;
        
	return TRUE;
}

/**
 * Tell everyone a new TCP session started.
 * Call the defined callback functions, alerting that a new TCP session was
 * created.
 * @see AddSessionCreateHandler
 */
void CallCreateFuncs(PP* Port) {
	SFunc*  F;

	DEBUGPATH;

	F = CreateFuncs;
        
	while (F) {
		F->Func(Port, F->Data);
		F = F->Next;
	}
}

/**
 * Tell everyone a TCP session ended.
 * Call the defined callback functions, alerting that a new TCP session was
 * ended.
 * @see AddSessionDestroyHandler
 */
void CallDestroyFuncs(PP* Port) {
	SFunc*	F;

	DEBUGPATH;

	F = DestroyFuncs;
	
	while (F) {
		F->Func(Port, F->Data);
		F = F->Next;
	}
}

/**
 * Generates a hash value for 2 IP addresses. Used in the Session[] array.
 * @see FindIPPair
 */
unsigned short GetHash(unsigned int ip1, unsigned int ip2) {
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

	return hash;
}

/**
 * Find the IP Pair that represents the connection between two IPs.
 * If it doesn't exist, create it.
 * Note: AssignSessionTCP() calls this function with the (numeric) least IP
 * first, so if two machines have two TCP sessions between them, in both 
 * directions, they will go under the same IPPair.
 */
IPP* FindIPPair(unsigned int IP1, unsigned int IP2) {
	unsigned short	Hash;
	IPB*			Bin;
	IPP*			Pair;
	int				i;
	unsigned int	Top, Bottom, Middle;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("%s-",inet_ntoa(*(struct in_addr*)&IP1));
	printf("%s\n",inet_ntoa(*(struct in_addr*)&IP2));
#endif

	Hash = GetHash(IP1, IP2);

	if (!Sessions[Hash]) {
#ifdef DEBUG
		printf("First IP Pair in this bin %u\n", Hash);
#endif	
		Sessions[Hash] = calloc(sizeof(IPB),1);
		if (!Sessions[Hash]) {
			fprintf(stderr, "Out of memory allocating a new TCP session\n");
			return NULL;
		}
		
		Bin = Sessions[Hash];
		Bin->NumAllocated = IP_START;
		Bin->NumIPs = 1;
		Bin->Pairs = calloc(sizeof(IPP*),IP_START+1);
		
		Bin->Pairs[0] = calloc(sizeof(IPP),1);
		Pair = Bin->Pairs[0];
		
		Pair->IP1 = IP1;
		Pair->IP2 = IP2;
		Pair->NumAllocated = 0;
		Pair->NumPorts = 0;
		Pair->Parent = Bin;
		
		return Pair;
	}
	
	/* replace this with a binary search after stable */
	Bin = Sessions[Hash];
	
	Top = Bin->NumIPs-1;
	Bottom = 0;
	Middle = Bottom+((Top-Bottom)/2);
	
	do {
		Pair = Bin->Pairs[Middle];
		
		if (!Pair) {
			printf("Pair was NULL. Tree corrupt\n");
			return NULL;
		}
		
		if ((Pair->IP1 == IP1) && (Pair->IP2 == IP2)) {
#ifdef DEBUG
			printf("Found Pair in Bin %i Slot %i\n",Hash, Middle);
#endif				
			return Pair;
		}
		
		if ( (IP1 < Pair->IP1) || ( (IP1 == Pair->IP1) && (IP2 < Pair->IP2)) ) {
			if (Top == Bottom) break;
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom) break;
			
			Bottom = Middle + 1;
			Middle = Bottom + ((Top-Bottom)/2);
		}
	} while (1);
	

#ifdef DEBUG
	printf("Creating new pair\n");
#endif
	
	if (Bin->NumIPs == Bin->NumAllocated) {
		/* Not found, create a new one */
		Bin->Pairs = realloc(Bin->Pairs, sizeof(IPP*)*(Bin->NumAllocated+IP_GROW+2));
		if (!Bin->Pairs) {
			fprintf(stderr, "Realloc of Bin->Pairs failed (TCP session)\n");
			exit(1);
		}
	
		/* Null out the new pointers */
		for (i = Bin->NumIPs; i < (Bin->NumAllocated+IP_GROW+1); i++) {
			Bin->Pairs[i] = NULL;
		}
	
		Bin->NumAllocated += IP_GROW;
	}

	if ( (IP1 > Pair->IP1) || ( (IP1 == Pair->IP1) && (IP2 > Pair->IP2)) )
		Middle++;
	
	memmove(&Bin->Pairs[Middle+1], &Bin->Pairs[Middle], sizeof(IPP*)*(Bin->NumIPs-Middle));
	
	Bin->Pairs[Middle] = calloc(sizeof(IPP),1);
	Pair = Bin->Pairs[Middle];
	Bin->NumIPs++;
	
	Pair->IP1 = IP1;
	Pair->IP2 = IP2;
	Pair->NumAllocated = 0;
	Pair->NumPorts = 0;
	Pair->Parent = Bin;
	
	return Pair;
}

/**
 * Add this session (port pair) to the "time list".
 * The "time list" is a linked list with the current sessions, meant to track
 * the time between the next packet in a session and the last one, to timeout
 * TCP sessions properly.
 */
int AddToTime(PP* Port) {

  DEBUGPATH;

	if (!TimeHead) {
		TimeHead = Port;
		TimeTail = Port;
		Port->TimeNext = NULL;
		Port->TimePrev = NULL;
		
		return TRUE;
	}
	
	if (!TimeTail) {
		fprintf(stderr, "Error: TimeTail was NULL.  Time chain is corrupted\n");
		return FALSE;
	}
	
	if (TimeTail->TimeNext) {
		fprintf(stderr, "Error: TimeTail->Next was not NULL.  Time chain is corrupted\n");
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
 * LastTime field since it should have been updated before calling this
 * function)
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
	Port->TimeNext=NULL;
	TimeTail->TimeNext=Port;
	Port->TimePrev=TimeTail;
	TimeTail=Port;
	
	return TRUE;
}


/**
 * Remove the TCP session (PortPair) from the bin.
 */
int RemovePort(PP* Port)
{
	IPP*			Pair;
	IPB*			Bin;
	int				Top, Bottom, Middle;
	unsigned short	Hash;
	
	DEBUGPATH;

#ifdef DEBUG_TIME
	printf("Freeing port with SessionID %u\n", Port->SessionID);
#endif

	/* tell everyone this is going away */
	CallDestroyFuncs(Port);

#ifdef TCP_STREAM_REASSEMBLY
	/* logs session */
	if (Globals.logSession_StartEnd) {
		//snprintf(Message, 1024, 
		printf(
			"End:%4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d dir:%d pcount:%d\n",
			Port->SessionID, inet_ntoa(*(struct in_addr*)&(Pair->IP1)), Port->Port1,
			inet_ntoa(*(struct in_addr*)&(Pair->IP2)), Port->Port2,
			Port->Direction, Port->TCPCount);
		//LogMessage(Message, &(Globals.logSessionFile));
  		}
#ifdef DEBUG
#define PAYLOADS_SIZE(s)	(s->LastSeq - s->TopSeq + 1)
	if (PAYLOADS_SIZE(Port->Stream0) > 0)
		DumpBuffer(Port->Stream0->Payloads, PAYLOADS_SIZE(Port->Stream0), stdout);
	if (PAYLOADS_SIZE(Port->Stream1) > 0)
		DumpBuffer(Port->Stream1->Payloads, PAYLOADS_SIZE(Port->Stream1), stdout);
#undef PAYLOADS_SIZE
#endif
#endif // TCP_STREAM_REASSEMBLY

	/* get pointers to parents */
	Pair = Port->Parent;
	Bin = Pair->Parent;

	/* remove from the time linked list */
	if ( (Port == TimeHead) && (Port == TimeTail) ) {
		/* only item in the list */
		if (Port->TimeNext || Port->TimePrev) {
			fprintf(stderr, "Error: Time chain is corrupt (RemovePort)\n");
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
		
		if ( (Port->Port1 < Pair->Ports[Middle]->Port1) || 
			 ( (Port->Port1 == Pair->Ports[Middle]->Port1) && (Port->Port2 < Pair->Ports[Middle]->Port2)) ) {
			if (Top == Bottom) {
				fprintf(stderr, "Error: Port not found in parent (RemovePort)\n");
				return FALSE;
			}
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom) {
				fprintf(stderr, "Error: Port not found in parent (RemovePort)\n");
				return FALSE;
			}
			
			Bottom = Middle + 1;
			Middle = Bottom + ((Top-Bottom)/2);
		}
	}
	
	/* remove this port from the ports list */
	memmove(&Pair->Ports[Middle], &Pair->Ports[Middle+1], sizeof(PP*)*(Pair->NumPorts-Middle-1));
	Pair->NumPorts--;
	Pair->Ports[Pair->NumPorts] = NULL;
	free(Port);
	Port = NULL;
	
	/* if the pair is empty, remove it as well */
	if (Pair->NumPorts > 0) 
		return TRUE;
	
	/* find this pair in the pairs list */
	Top = Bin->NumIPs-1;
	Bottom = 0;
	Middle = Bottom + ((Top-Bottom)/2);
	
	while (1) {
		if (Bin->Pairs[Middle] == Pair) {
			break;
		}
		
		if ( (Pair->IP1 < Bin->Pairs[Middle]->IP1) || 
			 ( (Pair->IP1 == Bin->Pairs[Middle]->IP1) && (Pair->IP2 < Bin->Pairs[Middle]->IP2)) ) {
			if (Top == Bottom) {
				fprintf(stderr, "Error: Pair not found in parent (RemovePort)\n");
				return FALSE;
			}
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom) {
				fprintf(stderr, "Error: Pair not found in parent (RemovePort)\n");
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
	if (Bin->NumIPs > 0) 
		return TRUE;
	
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
	int				i;
	PP*				Port;
	int				Top, Bottom, Middle;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("%u-%u",Port1, Port2);
#endif

	if (!Pair->Ports) {
#ifdef DEBUG
		printf("First Port Pair in this bin with sessionID %u\n", SessionCount);
#endif	
		Pair->Ports = calloc(sizeof(PP*), PORT_START+2);
		if (!Pair->Ports) {
			fprintf(stderr, "Error: Out of memory creating TCP session (FindPortPair)\n");
			return NULL;
		}
		
		Pair->NumAllocated = PORT_START;
		Pair->NumPorts = 1;
		Pair->Ports[0] = calloc(sizeof(PP),1);
		
		Port = Pair->Ports[0];

		Port->Port1 = Port1;
		Port->Port2 = Port2;		
		Port->Parent = Pair;
		Port->LastTime = Now;
		Port->FirstTime = Now;
		if (Port->SessionID) {
			fprintf(stderr, "Erro: SessionID was not 0 (FindPortPair)\n");
		}
		Port->SessionID = SessionCount;
				
		SessionCount++;
#ifdef DEBUG
		printf("There are %i sessions\n",SessionCount);
#endif		

		AddToTime(Port);

		/* Tell everyone this session exists */
		CallCreateFuncs(Port);

		return Port;
	}
	
	/* Binary search for the port */
	Top = Pair->NumPorts-1;
	Bottom = 0;
	Middle = Bottom + ((Top-Bottom)/2);
	
	do {
		if (Middle > Pair->NumAllocated) {
			fprintf(stderr, "Error: PortPair tree is corrupted (FindPortPair)\n");
			exit(1);
		}
		
		Port = Pair->Ports[Middle];
		if (!Port) {
			fprintf(stderr, "Error: Pointer was NULL Port %i (FindPortPair)\n", Middle);
			return NULL;
		}
		
		if ( (Port->Port1 == Port1) && (Port->Port2 == Port2) ) {
#ifdef DEBUG
			printf("Found Port in Slot %i\n",Middle);
#endif		
			Port->LastTime = Now;
			UpdateTime(Port);
			return Port;
		}
		
		if ( (Port1 < Port->Port1) || ( (Port1 == Port->Port1) && (Port2 < Port->Port2) ) ) {
			if (Top == Bottom) break;
			
			Top = Middle;
			Middle = Bottom + ((Top-Bottom)/2);
		} else {
			if (Top == Bottom) break;
			
			Bottom = Middle + 1;
			Middle=Bottom+((Top-Bottom)/2);
		}
	} while(1);
	
#ifdef DEBUG
	printf("Creating new port with sessionID %u\n", SessionCount);
#endif

	if (Pair->NumPorts == Pair->NumAllocated) {
		/* allocate some more ports */
		Pair->Ports = realloc(Pair->Ports, sizeof(PP*)*(Pair->NumAllocated+PORT_GROW+2));
		if (!Pair->Ports) {
			fprintf(stderr, "Error: realloc failed (FindPortPair)\n");
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
		fprintf(stderr, "Error: SessionID was not NULL (FindPortPair)\n");
	}	
	Port->SessionID = SessionCount;

#ifdef TCP_STREAM_REASSEMBLY
	if (Globals.logSession_StartEnd) {
		logbuf = GetLogBuffer();
		snprintf(LogBuffer(logbuf), MAX_LOGBUFFER_SIZE, 
		       "Start %4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d dir:%d pcount:%d\n", 
		       Port->SessionID,
#ifdef HLBR_LITTLE_ENDIAN
		       (Pair->IP1 & 0x000000ff), (Pair->IP1 & 0x0000ff00)>>8, (Pair->IP1 & 0x00ff0000)>>16, Pair->IP1>>24, Port->Port1,
		       (Pair->IP2 & 0x000000ff), (Pair->IP2 & 0x0000ff00)>>8, (Pair->IP2 & 0x00ff0000)>>16, Pair->IP2>>24, Port->Port2,
#else
		       Pair->IP1>>24, (Pair->IP1 & 0x00ff0000)>>16, (Pair->IP1 & 0x0000ff00)>>8, (Pair->IP1 & 0x000000ff), Port->Port1, 
		       Pair->IP2>>24, (Pair->IP2 & 0x00ff0000)>>16, (Pair->IP2 & 0x0000ff00)>>8, (Pair->IP2 & 0x000000ff), Port->Port2, 
#endif
		       //(TData->Header->syn ? 's' : '.'), (TData->Header->ack ? 'a' : '.'),
		       Port->Direction, Port->TCPCount);
		FlushLogBuffer(logbuf, Globals.logSession);
  	}	
#endif // TCP_STREAM_REASSEMBLY

	AddToTime(Port);
	
	SessionCount++;
#ifdef DEBUG
	printf("There are %i sessions\n",SessionCount);
#endif	

	/* Tell everyone this session exists */
	CallCreateFuncs(Port);
	
	return Port;
}

/**
 * Free up the sessions (port pairs) that are expired.
 * Searches the "time list" and frees up sessions that timed out, i.e. sessions
 * where the time between a packet and the next one took longer than the set
 * timeout for a TCP session.
 */
int TimeoutSessions(long int Now)
{
	PP*	TimeNext;
	
	DEBUGPATH;

/* Checks if there are pending sessions with just one packet waiting;
   this probably is the last packet in a TCP session, so let it go */
	while (TimeHead && (TimeHead->LastTime + SESSION_FORCE_TIMEOUT < Now)) {
		//TODO: add this & check Stream1 also?
		//if (TimeHead->Stream0 != NULL) {
		//	if (TimeHead->Stream0->NumPieces == 1)
		//		TCPSessionUnblock(TimeHead->Stream0
		TimeNext = TimeHead->TimeNext;	
		RemovePort(TimeHead);
		TimeHead = TimeNext;
	}

	return TRUE;
}


/**
 * Find the session (PortPair struct) for this TCP packet. 
 * This function is called for every TCP packet; it searches for its 
 * corresponding session, updates the state of both streams 
 * (cli->srv and srv->cli), and remounts the payload of the packets of this same
 * session, to apply checks upon the remounted buffer.
 */
int AssignSessionTCP(int PacketSlot, void* Data)
{
	IPData*			IData;
	TCPData*		TData;
	unsigned int	IP1,IP2;
	unsigned short	Port1, Port2;
	IPP*			Pair;
	PP*				Port;
#ifdef TCP_STREAM_REASSEMBLY
	struct tcp_stream*	Stream;
	char			reassemble = 0;	// try to remount this packet?
	char			outoforder = 0;	// packet isn't in the expected order?
#endif
	char 			strIP1[INET_ADDRSTRLEN];
	char			strIP2[INET_ADDRSTRLEN];
	
	DEBUGPATH;

	GetDataByID(PacketSlot, IPDecoderID, (void**)&IData);
	if (!IData) {
		fprintf(stderr, "Error: AssignSessionTCP received a non-IP packet\n");
		return FALSE;
	}

	TData = (TCPData*)Data;
	if (!TData){
		fprintf(stderr, "Error: AssignSessionTCP receibed a packet with NULL TCP Data\n");
		return FALSE;
	}

	/* Assigns IP1 & IP2; IP1 is the lesser of the src & dst IPs */
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

	//printf("AssignSession received: %i:%i <-> %i:%i\n", IP1, Port1, IP2, Port2);

	/* Finds a pair of IPs in the IP Pair Bin */
	Pair = FindIPPair(IP1, IP2);
	if (!Pair) {
		inet_ntop(AF_INET, (struct in_addr*)&IP1, strIP1, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (struct in_addr*)&IP2, strIP2, INET_ADDRSTRLEN);
		fprintf(stderr, "Failed to assign session IP pair for %s:%d <-> %s:%d\n",
				strIP1, Port1, strIP2, Port2);
		return FALSE;
	}
	/* Finds a session (a pair of ports in the pair of IPs) in the Bin */
	Port = FindPortPair(Port1, Port2, Pair, Globals.Packets[PacketSlot].tv.tv_sec);
	if (!Port) {
		inet_ntop(AF_INET, (struct in_addr*)&IP1, strIP1, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (struct in_addr*)&IP2, strIP2, INET_ADDRSTRLEN);
		fprintf(stderr, "Failed to assign session port for %s:%d <-> %s:%d\n",
				strIP1, Port1, strIP2, Port2);
		return FALSE;
	}

	/* Discover the direction and state of this session */
  		
#ifdef TCP_STREAM_REASSEMBLY
#ifdef DEBUG_DIRECTION
	PrintPacketSummary(stdout, PacketSlot, IData, TData, '\n');
#endif		
#endif

	if ( (Port->ServerState == TCP_STATE_NEW) && (Port->ClientState == TCP_STATE_NEW) ) {
		/***************************************************/
		/*we don't know what direction or state this is yet*/
		/*                                                 */
		/*If it starts with a SYN:                         */
		/*  Sender is Client, State is SYN                 */
		/*If it starts with a SYN|ACK                      */
		/*  Sender is Server, State is SYN|ACK             */
		/*If it starts with a FIN:                         */
		/*  Sender is Client, State is DATA, FIN Set for Client */
		/*If it starts with a RST:                         */
		/*  Sender is Server, State is RESET               */
		/*If it starts with a normal ACK                   */
		/*  Sender is Client, State is DATA                */
		/***************************************************/
		
		if (TData->Header->syn && !(TData->Header->ack || TData->Header->fin || TData->Header->rst) ) {
#ifdef DEBUG_DIRECTION
			printf("\tSYN start\n");
#endif		
			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP2_SERVER;
			} else {
				Port->Direction = SESSION_IP1_SERVER;
			}
			
			Port->ClientState = TCP_STATE_SYN;
			Port->ClientSeq = ntohl(TData->Header->seq);
			Port->ClientAck = ntohl(TData->Header->ack_seq);
		} else if (TData->Header->syn && TData->Header->ack && !(TData->Header->fin || TData->Header->rst) ) {
#ifdef DEBUG_DIRECTION
			printf("\tSYN|ACK start\n");
#endif		
			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP1_SERVER;
			}else{
				Port->Direction = SESSION_IP2_SERVER;
			}
			
			Port->ServerState = TCP_STATE_SYNACK;
			Port->ServerSeq = ntohl(TData->Header->seq);
			Port->ServerAck = ntohl(TData->Header->ack_seq);
		} else if (TData->Header->rst) {
#ifdef DEBUG_DIRECTION
			printf("\tRST start\n");
#endif
			if (IP1 == IData->Header->saddr) {
				Port->Direction = SESSION_IP1_SERVER;
			}else{
				Port->Direction = SESSION_IP2_SERVER;
			}
			
			Port->ServerState=TCP_STATE_RESET;
			Port->ServerSeq=ntohl(TData->Header->seq);
			Port->ServerAck=ntohl(TData->Header->ack_seq);
		}else if (TData->Header->fin){
#ifdef DEBUG_DIRECTION
			printf("Started with a FIN\n");
#endif		
			if (IP1==IData->Header->saddr){
				Port->Direction=SESSION_IP2_SERVER;
			}else{
				Port->Direction=SESSION_IP1_SERVER;
			}
			
			Port->ClientState=TCP_STATE_DATA;
			Port->ClientSeq=ntohl(TData->Header->seq);
			Port->ClientAck=ntohl(TData->Header->ack_seq);			
		}else{
#ifdef DEBUG_DIRECTION
			printf("Startup in the middle of a session\n");
#endif		
			if (IP1==IData->Header->saddr){
				Port->Direction=SESSION_IP2_SERVER;
			}else{
				Port->Direction=SESSION_IP1_SERVER;
			}
			
			Port->ClientState=TCP_STATE_DATA;
			Port->ServerState=TCP_STATE_DATA;
			Port->ClientSeq=ntohl(TData->Header->seq);
			Port->ClientAck=ntohl(TData->Header->ack_seq);					
		}
	}else{
		/*see if this came from the client or the server*/
		if (
			((Port->Direction==SESSION_IP1_SERVER) && (IData->Header->saddr==IP1)) ||
			((Port->Direction==SESSION_IP2_SERVER) && (IData->Header->saddr==IP2))
		){
#ifdef DEBUG		
			printf("This packet came from the server\n");
#endif			
			/*this packet came from the server*/

			if ( (Port->ClientState==TCP_STATE_FIN) && (Port->ServerState==TCP_STATE_FIN) && !(TData->Header->fin || TData->Header->syn || TData->Header->rst) ){
#ifdef DEBUG_DIRECTION
				printf("Final ACK\n");
#endif
				if ( (Port->ClientSeq+1) != ntohl(TData->Header->ack_seq)){
					//printf("Seq didn't match\n");
				}
				Port->ClientState=TCP_STATE_LATE;
				Port->ServerState=TCP_STATE_LATE;
			}else if (TData->Header->syn && TData->Header->ack  && !(TData->Header->rst || TData->Header->fin) ){
				/*************************/
				/*syn|ack from the server*/
				/*************************/
				if ( (Port->ServerState==TCP_STATE_NEW) && (Port->ClientState==TCP_STATE_SYN)){
#ifdef DEBUG_DIRECTION
					printf("Normal SYN|ACK\n");
#endif		
					Port->ServerState=TCP_STATE_SYNACK;
					Port->ServerSeq=ntohl(TData->Header->seq);
					Port->ServerAck=ntohl(TData->Header->ack_seq);
					
					if (Port->ServerAck != (Port->ClientSeq+1) ){
#ifdef DEBUG
						printf("SYN|ACK didn't match\n");
#endif							
						Port->Error=TRUE;
					}
				}else if (Port->ServerState==TCP_STATE_SYNACK){
#ifdef DEBUG_DIRECTION
					printf("Resend of the SYN|ACK\n");
#endif						
					if ( (Port->ServerSeq!=ntohl(TData->Header->seq)) || (Port->ServerAck!=ntohl(TData->Header->ack_seq)) ){
#ifdef DEBUG
						printf("Reset SYN|ACK didn't match orginal\n");
#endif					
						Port->Error=TRUE;
					}
				}
			}else if (TData->Header->rst){
#ifdef DEBUG_DIRECTION
				printf("Server sent a RESET\n");
#endif						
				Port->ServerState=TCP_STATE_RESET;
				Port->ServerSeq=ntohl(TData->Header->seq);
				Port->ServerAck=ntohl(TData->Header->ack_seq);
			}else if (TData->Header->fin){
#ifdef DEBUG_DIRECTION
				printf("Server sent a FIN\n");
#endif						
				Port->ServerState=TCP_STATE_FIN;
				Port->ServerSeq=ntohl(TData->Header->seq);
				Port->ServerAck=ntohl(TData->Header->ack_seq);
				Port->ServerFin=1;
			}else{
				if ( (Port->ServerState==TCP_STATE_SYNACK) && (Port->ClientState=TCP_STATE_DATA) ){
#ifdef DEBUG_DIRECTION
					printf("First Data packet from server\n");
#endif							
					Port->ServerState=TCP_STATE_DATA;
					Port->ServerSeq=ntohl(TData->Header->seq);
					Port->ServerAck=ntohl(TData->Header->ack_seq);
				}else if (Port->ServerState==TCP_STATE_DATA){
#ifdef DEBUG_DIRECTION
					printf("Normal Data from Server\n");
#endif							
					Port->ServerSeq=ntohl(TData->Header->seq);
					Port->ServerAck=ntohl(TData->Header->ack_seq);				
				}else{
#ifdef DEBUG_DIRECTION
					printf("Error:  This packet was unexpected\n");
#endif			
					Port->Error=TRUE;
				}
			}
		}else{
#ifdef DEBGU		
			printf("This packet came from the client\n");
#endif			
			/*this packet came from the client*/
			
			if ( (Port->ClientState==TCP_STATE_FIN) && (Port->ServerState==TCP_STATE_FIN) && !(TData->Header->fin || TData->Header->syn || TData->Header->rst) ){
#ifdef DEBUG_DIRECTION
				printf("Final ACK\n");
#endif
				if ( (Port->ServerSeq+1) != ntohl(TData->Header->ack_seq)){
					//printf("Seq didn't match\n");
				}
				Port->ClientState=TCP_STATE_LATE;
				Port->ServerState=TCP_STATE_LATE;
			}else if (!(TData->Header->fin || TData->Header->rst) ){
				if ( (Port->ClientState==TCP_STATE_SYN) && (Port->ServerState==TCP_STATE_SYNACK) ){
				/************************/
				/* Acking the SYN|ACK   */
				/************************/ 
#ifdef DEBUG_DIRECTION
					printf("Normal SYN|ACK ACK\n");
#endif		
					Port->ClientState=TCP_STATE_DATA;
					Port->ClientSeq=ntohl(TData->Header->seq);
					Port->ClientAck=ntohl(TData->Header->ack_seq);
				}else if (Port->ClientState==TCP_STATE_DATA){
#ifdef DEBUG_DIRECTION
					printf("Normal Client Traffic\n");
#endif							
					Port->ClientSeq=ntohl(TData->Header->seq);
					Port->ClientAck=ntohl(TData->Header->ack_seq);
				}else{
#ifdef DEBUG_DIRECTION
					printf("Error:  This packet was unexpected\n");
#endif							
				}
			}else if (TData->Header->rst){
#ifdef DEBUG_DIRECTION
				printf("Client sent a RST\n");
#endif										
				Port->ClientState=TCP_STATE_RESET;
			}else if (TData->Header->fin){
#ifdef DEBUG_DIRECTION
					printf("Client sent a FIN\n");
#endif			
				Port->ClientState=TCP_STATE_FIN;
			}else{
#ifdef DEBUG_DIRECTION
				printf("Error:  This packet was unexpected\n");
#endif										
			}
		}
	}

		
	/*update stats and pointers*/
	Port->TCPCount++;
	Globals.Packets[PacketSlot].Stream=Port;

	TimeoutSessions(Globals.Packets[PacketSlot].tv.tv_sec);

	return TRUE;
}

/**
 * Sets up the session handler.
 * Global variable IPB holds info about all identified sessions. 
 */
int InitSession(){

  DEBUGPATH;

	bzero(Sessions, sizeof(IPB*)*65536);
	TimeHead=NULL;
	CreateFuncs=NULL;
	DestroyFuncs=NULL;

	IPDecoderID=GetDecoderByName("IP");
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}




#ifdef DEBUG
#undef DEBUG
#endif
#ifdef DEBUG_TIME
#undef DEBUG_TIME
#endif
#ifdef DEBUG_DIRECTION
#undef DEBUG_DIRECTION
#endif
