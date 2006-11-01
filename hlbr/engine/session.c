#include "session.h"
#include "hlbrlib.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*+++++++++++++++++++Globals+++++++++++++++++*/
IPB*			Sessions[65536+1]; /**< All identified sessions. @see InitSession() */
int			TCPDecoderID;
int			IPDecoderID;
unsigned int		SessionCount=0;
SFunc*			CreateFuncs;
SFunc*			DestroyFuncs;
extern	GlobalVars	Globals;

PP*			TimeHead;
PP*			TimeTail;

//#define DEBUG
//#define DEBUG_TIME
//#define DEBUG_DIRECTION

/**
 * Prints a one-line summary of the packet
 * Inspects packet's IP and TCP structure (if any)
 */
void PrintPacketSummary(FILE* stream, int PacketSlot, IPData* IData, TCPData* TData, char newline)
{
	if (!IData) {
		fprintf(stream, "P:%u -%c", PacketSlot,
		       (newline ? '\n' : ' '));
		return;
	}
	if (!TData) {
		fprintf(stream, "P:%u IP %d.%d.%d.%d->%d.%d.%d.%d%c", PacketSlot,
		       IP_BYTES(IData->Header->saddr), IP_BYTES(IData->Header->daddr),
		       (newline ? '\n' : ' '));
		return;
	}
	fprintf(stream, "P:%u TCP %d.%d.%d.%d:%d->%d.%d.%d.%d:%d%c", PacketSlot,
	       IP_BYTES(IData->Header->saddr), TData->Header->source,
	       IP_BYTES(IData->Header->daddr), TData->Header->dest,
	       (newline ? '\n' : ' '));
	return;
}


/****************************************
* Add function that gets called whenever a
* session is created
*****************************************/
int AddSessionCreateHandler(void (*Func) (PP* Port, void* Data), void* Data){
	SFunc*	F;
#ifdef DEBUGPATH
	printf("In AddSessionCreateHandler\n");
#endif

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
	
#ifdef DEBUGPATH
	printf("In AddSessionDestroyHandler\n");
#endif

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

/***************************************
* Tell everyone a new session started
***************************************/
void CallCreateFuncs(PP* Port){
	SFunc*	F;
#ifdef DEBUGPATH
	printf("In CallCreateFuncs\n");
#endif

	F=CreateFuncs;
	
	while (F){
		F->Func(Port, F->Data);
		F=F->Next;
	}
}

/***************************************
* Tell everyone a new session ended
***************************************/
void CallDestroyFuncs(PP* Port){
	SFunc*	F;
#ifdef DEBUGPATH
	printf("In CallDestroyFuncs\n");
#endif

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
	
#ifdef DEBUGPATH
	printf("In GetHash\n");
#endif

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
	
#ifdef DEBUGPATH
	printf("In FindIPPair\n");
#endif

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
	Bin=Sessions[Hash];
	
	Top=Bin->NumIPs-1;
	Bottom=0;
	Middle=Bottom+((Top-Bottom)/2);
	
	do{
		Pair=Bin->Pairs[Middle];
		
		if (!Pair){
			printf("Pair was NULL. Tree corrupt\n");
			return NULL;
		}
		
		if ((Pair->IP1==IP1) && (Pair->IP2==IP2)){
#ifdef DEBUG
			printf("Found Pair in Bin %i Slot %i\n",Hash, Middle);
#endif				
			return Pair;
		}
		
		if ( (IP1<Pair->IP1) || ( (IP1==Pair->IP1) && (IP2<Pair->IP2)) ){
			if (Top==Bottom) break;
			
			Top=Middle;
			Middle=Bottom+((Top-Bottom)/2);
		}else{
			if (Top==Bottom) break;
			
			Bottom=Middle+1;
			Middle=Bottom+((Top-Bottom)/2);
		}
	} while (1);
	

#ifdef DEBUG
	printf("Creating new pair\n");
#endif
	
	if (Bin->NumIPs==Bin->NumAllocated){
		/*Not found, create a new one*/
		Bin->Pairs=realloc(Bin->Pairs, sizeof(IPP*)*(Bin->NumAllocated+IP_GROW+2));
		if (!Bin->Pairs){
			printf("realloc failed\n");
			exit(1);
		}
	
		/*Null out the new pointers*/
		for (i=Bin->NumIPs;i<(Bin->NumAllocated+IP_GROW+1);i++){
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

/************************************
* Add this to the time list
************************************/
int AddToTime(PP* Port){
#ifdef DEBUGPATH
	printf("In AddToTime\n");
#endif

	if (!TimeHead){
		TimeHead=Port;
		TimeTail=Port;
		Port->TimeNext=NULL;
		Port->TimePrev=NULL;
		
		return TRUE;
	}
	
	if (!TimeTail){
		printf("Error: TimeTail was NULL.  Time chain is corrupted\n");
		return FALSE;
	}
	
	if (TimeTail->TimeNext){
		printf("Error: TimeTail->Next was not NULL.  Time chain is corrupted\n");
		return FALSE;
	}
	
	TimeTail->TimeNext=Port;
	Port->TimePrev=TimeTail;
	Port->TimeNext=NULL;
	TimeTail=Port;

	return TRUE;
}

/************************************
* move this to the end of the list
************************************/
int UpdateTime(PP* Port){

#ifdef DEBUGPATH
	printf("In UpdateTime\n");
#endif

	if (TimeTail==Port){
		/*already the last*/
		return TRUE;
	}

	if (TimeHead==Port){
		if (Port->TimeNext==NULL){
			/*only item in chain*/
			return TRUE;
		}
		
		TimeHead=TimeHead->TimeNext;
		TimeHead->TimePrev=NULL;
		
		TimeTail->TimeNext=Port;
		Port->TimeNext=NULL;
		Port->TimePrev=TimeTail;
		TimeTail=Port;
		
		return TRUE;
	}
	
	Port->TimePrev->TimeNext=Port->TimeNext;
	Port->TimeNext->TimePrev=Port->TimePrev;
	Port->TimeNext=NULL;
	TimeTail->TimeNext=Port;
	Port->TimePrev=TimeTail;
	TimeTail=Port;
	
	return TRUE;
}


/************************************
* Get rid of this port
************************************/
int RemovePort(PP* Port){
	IPP*			Pair;
	IPB*			Bin;
	int				Top, Bottom, Middle;
	unsigned short	Hash;
	
#ifdef DEBUGPATH
	printf("In RemovePort\n");
#endif

#ifdef DEBUG_TIME
	printf("Freeing port with SessionID %u\n", Port->SessionID);
#endif

	/*tell everyone this is going away*/
	CallDestroyFuncs(Port);

	/*get pointers to parents*/
	Pair=Port->Parent;
	Bin=Pair->Parent;

	/*remove from the time linked list*/
	if ( (Port==TimeHead) && (Port==TimeTail) ){
		/*only item in the list*/
		if (Port->TimeNext || Port->TimePrev){
			printf("Error Time chain is corrupt\n");
			return FALSE;
		}
		
		TimeHead=NULL;
		TimeTail=NULL;
	}else if (Port==TimeHead){
		Port->TimeNext->TimePrev=NULL;
		TimeHead=Port->TimeNext;
	}else if (Port==TimeTail){
		Port->TimePrev->TimeNext=NULL;
		TimeTail=Port->TimePrev;
	}else{
		Port->TimePrev->TimeNext=Port->TimeNext;
		Port->TimeNext->TimePrev=Port->TimePrev;
	}
	Port->TimeNext=NULL;
	Port->TimePrev=NULL;

	/*find the entry in the ports list*/
	Top=Pair->NumPorts-1;
	Bottom=0;
	Middle=Bottom+((Top-Bottom)/2);
	
	while (1){	
		if (Pair->Ports[Middle]==Port){
			break;
		}
		
		if ( (Port->Port1<Pair->Ports[Middle]->Port1) || ( (Port->Port1==Pair->Ports[Middle]->Port1) && (Port->Port2<Pair->Ports[Middle]->Port2)) ){
			if (Top==Bottom){
				printf("Error: Port not found in parent\n");
				return FALSE;
			}
			
			Top=Middle;
			Middle=Bottom+((Top-Bottom)/2);
		}else{
			if (Top==Bottom){
				printf("Error: Port not found in parent\n");
				return FALSE;
			}
			
			Bottom=Middle+1;
			Middle=Bottom+((Top-Bottom)/2);
		}
	}
	
	/*remove this port from the ports list*/
	memmove(&Pair->Ports[Middle], &Pair->Ports[Middle+1], sizeof(PP*)*(Pair->NumPorts-Middle-1));
	Pair->NumPorts--;
	Pair->Ports[Pair->NumPorts]=NULL;
	free(Port);
	Port=NULL;
	
	/*if the pair is empty, remove it as well*/
	if (Pair->NumPorts>0) return TRUE;
	
	/*find this pair in the pairs list*/
	Top=Bin->NumIPs-1;
	Bottom=0;
	Middle=Bottom+((Top-Bottom)/2);
	
	while (1){
		if (Bin->Pairs[Middle]==Pair){
			break;
		}
		
		if ( (Pair->IP1<Bin->Pairs[Middle]->IP1) || ( (Pair->IP1==Bin->Pairs[Middle]->IP1) && (Pair->IP2<Bin->Pairs[Middle]->IP2)) ){
			if (Top==Bottom){
				printf("Error: Pair not found in parent\n");
				return FALSE;
			}
			
			Top=Middle;
			Middle=Bottom+((Top-Bottom)/2);
		}else{
			if (Top==Bottom){
				printf("Error: Pair not found in parent\n");
				return FALSE;
			}
			
			Bottom=Middle+1;
			Middle=Bottom+((Top-Bottom)/2);
		}
	}
	
	/*remove this pair from the bin*/
	memmove(&Bin->Pairs[Middle], &Bin->Pairs[Middle+1], sizeof(IPP*)*(Bin->NumIPs-Middle-1));
	Bin->NumIPs--;
	Bin->Pairs[Bin->NumIPs]=NULL;
	
	Hash=GetHash(Pair->IP1, Pair->IP2);
	
	free(Pair->Ports);
	Pair->Ports=NULL;
	free(Pair);
	Pair=NULL;	
	
	/*if the bin is empty, remove it*/
	if (Bin->NumIPs>0) return TRUE;
	
	free(Bin->Pairs);
	Bin->Pairs=NULL;
	free(Sessions[Hash]);
	Sessions[Hash]=NULL;
	
	return TRUE;
}

/************************************
* Find the Port Pair, if it doesn't 
* exist, create it
************************************/
PP* FindPortPair(unsigned short Port1, unsigned short Port2, IPP* Pair, long int Now){
	int				i;
	PP*				Port;
	int				Top, Bottom, Middle;
	
#ifdef DEBUGPATH
	printf("In FindPortPair\n");
#endif

	if (!Pair->Ports){
#ifdef DEBUG
		printf("First Port Pair in this bin with sessionID %u\n", SessionCount);
#endif	
		Pair->Ports=calloc(sizeof(PP*), PORT_START+2);
		if (!Pair->Ports){
			printf("Out of memory\n");
			return NULL;
		}
		
		Pair->NumAllocated=PORT_START;
		Pair->NumPorts=1;
		Pair->Ports[0]=calloc(sizeof(PP),1);
		
		Port=Pair->Ports[0];

		Port->Port1=Port1;
		Port->Port2=Port2;		
		Port->Parent=Pair;
		Port->LastTime=Now;
		Port->FirstTime=Now;
		if (Port->SessionID){
			printf("SessionID was not 0\n");
		}
		Port->SessionID=SessionCount;
		Port->TheOtherPortPair = NULL;
				
		SessionCount++;
#ifdef DEBUG1
		printf("There are %i sessions\n",SessionCount);
#endif		

		AddToTime(Port);

		if (Globals.logSession_BeginEnd)
			printf("LS:%4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d dir:%d pcount:%d\n", 
			       Port->SessionID, IP_BYTES(Pair->IP1), Port->Port1,
			       IP_BYTES(Pair->IP2), Port->Port2,
//		       (TData->Header->syn ? 's' : '.'),
//     		       (TData->Header->ack ? 'a' : '.'),
			       Port->Direction, Port->TCPCount);

		/*Tell everyone this session exists*/
		CallCreateFuncs(Port);
		
		return Port;
	}
	
	/*Binary search for the port*/
	Top=Pair->NumPorts-1;
	Bottom=0;
	Middle=Bottom+((Top-Bottom)/2);
	
	do {
		if (Middle>Pair->NumAllocated){
			printf("Tree is corrupted\n");
			exit(1);
		}
		
		Port=Pair->Ports[Middle];
		if (!Port){
			printf("Error: Pointer was NULL Port %i\n", Middle);
			return NULL;
		}
		
		if ( (Port->Port1==Port1) && (Port->Port2==Port2) ){
#ifdef DEBUG
			printf("Found Port in Slot %i\n",Middle);
#endif		
			Port->LastTime=Now;
			UpdateTime(Port);
			return Port;
		}
		
		if ( (Port1<Port->Port1) || ( (Port1==Port->Port1) && (Port2<Port->Port2) ) ){
			if (Top==Bottom) break;
			
			Top=Middle;
			Middle=Bottom+((Top-Bottom)/2);
		}else{
			if (Top==Bottom) break;
			
			Bottom=Middle+1;
			Middle=Bottom+((Top-Bottom)/2);
		}
	} while(1);
	
#ifdef DEBUG
	printf("Creating new port with sessionID %u\n", SessionCount);
#endif

	if (Pair->NumPorts==Pair->NumAllocated){	
		/*allocate some more ports*/
		Pair->Ports=realloc(Pair->Ports, sizeof(PP*)*(Pair->NumAllocated+PORT_GROW+2));
		if (!Pair->Ports){
			printf("realloc failed\n");
			exit(1);
		}
	
		/*Null out the new pointers*/
		for (i=Pair->NumPorts;i<(Pair->NumAllocated+PORT_GROW+1);i++){
			Pair->Ports[i]=NULL;
		}
	
		Pair->NumAllocated+=PORT_GROW;
	}
	
	if ((Port1>Port->Port1) || ( (Port1==Port->Port1) && (Port2>Port->Port2) ) )
		Middle++;
	
	memmove(&Pair->Ports[Middle+1], &Pair->Ports[Middle], sizeof(PP*)*(Pair->NumPorts-Middle));
	
	Pair->Ports[Middle]=calloc(sizeof(PP),1);
	Port=Pair->Ports[Middle];
	Pair->NumPorts++;

	Port->Port1=Port1;
	Port->Port2=Port2;	
	Port->Parent=Pair;
	Port->LastTime=Now;
	Port->FirstTime=Now;
	if (Port->SessionID){
		printf("SessionID was not NULL\n");
	}	
	Port->SessionID=SessionCount;
	Port->TheOtherPortPair = NULL;


	if (Globals.logSession_BeginEnd)
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
#ifdef DEBUG1
	printf("There are %i sessions\n",SessionCount);
#endif	

	/*Tell everyone this session exists*/
	CallCreateFuncs(Port);
	
	return Port;
}

/***********************************
* Free up the nodes that are expired
***********************************/
int TimeoutSessions(long int Now){
	PP*	TimeNext;
	
#ifdef DEBUGPATH
	printf("In TimeoutSessions\n");
#endif

	while (TimeHead && 	(TimeHead->LastTime+SESSION_FORCE_TIMEOUT<Now)){
		TimeNext=TimeHead->TimeNext;	
		RemovePort(TimeHead);
		TimeHead=TimeNext;
	}

	return TRUE;
}


/**
 * Find the session for this TCP packet.
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
#ifdef DEBUGPATH
	printf("In AssignSessionTCP\n");
#endif

	GetDataByID(PacketSlot, IPDecoderID, (void**)&IData);
	if (!IData){
		PrintPacketSummary(stderr, PacketSlot, IData, NULL, false);
		fprintf(stderr, "This was supposed to be a TCP packet\n");
		return FALSE;
	}

	TData=(TCPData*)Data;
	if (!TData){
		PrintPacketSummary(stderr, PacketSlot, IData, TData, false);
		fprintf(stderr, "TCP Data was NULL\n");
		return FALSE;
	}

	// Assigns IP1 & IP2: IP1 is the lesser of the src & dst IPs
	if (IData->Header->saddr < IData->Header->daddr){
		IP1=IData->Header->saddr;
		IP2=IData->Header->daddr;
		Port1=ntohs(TData->Header->source);
		Port2=ntohs(TData->Header->dest);
	}else{
		IP1=IData->Header->daddr;
		IP2=IData->Header->saddr;
		Port1=ntohs(TData->Header->dest);
		Port2=ntohs(TData->Header->source);
	}

	Pair = FindIPPair(IP1, IP2);
	if (!Pair){
		PrintPacketSummary(stderr, PacketSlot, IData, TData, false);
		fprintf(stderr, "Failed to assign session pair\n");
		return FALSE;
	}	
	Port = FindPortPair(Port1, Port2, Pair, Globals.Packets[PacketSlot].tv.tv_sec);
	if (!Port){
		PrintPacketSummary(stderr, PacketSlot, IData, TData, false);
		fprintf(stderr, "Failed to assign session port\n");
		return FALSE;
	}

	RemountTCPStream(PacketSlot, Port);

	if ( (Port->ServerState==TCP_STATE_NEW) && (Port->ClientState==TCP_STATE_NEW) ){
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
		
		if (TData->Header->syn && !(TData->Header->ack || TData->Header->fin || TData->Header->rst) ){
#ifdef DEBUG_DIRECTION
			printf("Started with a SYN\n");
#endif		
			if (IP1==IData->Header->saddr){
				Port->Direction=SESSION_IP2_SERVER;
			}else{
				Port->Direction=SESSION_IP1_SERVER;
			}
			
			Port->ClientState=TCP_STATE_SYN;
			Port->ClientSeq=ntohl(TData->Header->seq);
			Port->ClientAck=ntohl(TData->Header->ack_seq);
		}else if (TData->Header->syn && TData->Header->ack && !(TData->Header->fin || TData->Header->rst) ){
#ifdef DEBUG_DIRECTION
			printf("Started with a SYN|ACK\n");
#endif		
			if (IP1==IData->Header->saddr){
				Port->Direction=SESSION_IP1_SERVER;
			}else{
				Port->Direction=SESSION_IP2_SERVER;
			}
			
			Port->ServerState=TCP_STATE_SYNACK;
			Port->ServerSeq=ntohl(TData->Header->seq);
			Port->ServerAck=ntohl(TData->Header->ack_seq);
		}else if (TData->Header->rst){
#ifdef DEBUG_DIRECTION
			printf("Started with a RST\n");
#endif		
			if (IP1==IData->Header->saddr){
				Port->Direction=SESSION_IP1_SERVER;
			}else{
				Port->Direction=SESSION_IP2_SERVER;
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
					printf("Error:  This packet was unexpected (1)\n");
#endif			
					Port->Error=TRUE;
				}
			}
		}else{
#ifdef DEBUG		
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
					printf("Error:  This packet was unexpected (2)\n");
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
				printf("Error:  This packet was unexpected (3)\n");
#endif										
			}
		}
	}

		
	/*update stats and pointers*/
	Port->TCPCount++;
	Globals.Packets[PacketSlot].Stream=Port;
/*
	if (Globals.logSession_BeginEnd)
		printf("LS:%4x %d.%d.%d.%d:%d->%d.%d.%d.%d:%d %c%c dir:%d pcount:%d\n", 
		       Port->SessionID,
#ifdef HLBR_LITTLE_ENDIAN
		       (IP1 & 0x000000ff), (IP1 & 0x0000ff00)>>8, (IP1 & 0x00ff0000)>>16, IP1>>24, Port->Port1,
		       (IP2 & 0x000000ff), (IP2 & 0x0000ff00)>>8, (IP2 & 0x00ff0000)>>16, IP2>>24, Port->Port2,
#else
		       IP1>>24, (IP1 & 0x00ff0000)>>16, (IP1 & 0x0000ff00)>>8, (IP1 & 0x000000ff), Port->Port1, 
		       IP2>>24, (IP2 & 0x00ff0000)>>16, (IP2 & 0x0000ff00)>>8, (IP2 & 0x000000ff), Port->Port2, 
#endif
		       (TData->Header->syn ? 's' : '.'),
		       (TData->Header->ack ? 'a' : '.'),
		       Port->Direction, Port->TCPCount);
*/
	TimeoutSessions(Globals.Packets[PacketSlot].tv.tv_sec);

	return TRUE;
}

/**
 * Sets up the session handler.
 * Global variable IPB holds all info about identified sessions.
 * @see ip_bin
 * @see ip_pair
 * @see port_pair
 */
int InitSession(){

#ifdef DEBUGPATH
	printf("In InitSession\n");
#endif

	bzero(Sessions, sizeof(IPB*)*65536);
	TimeHead=NULL;
	CreateFuncs=NULL;
	DestroyFuncs=NULL;

	IPDecoderID=GetDecoderByName("IP");
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}


#ifdef TCP_STREAM

/**
 * Remounts packets in a TCP stream and check them together for signatures
 * @see tcp_stream_buffer
 */
int RemountTCPStream(int PacketSlot, PP* Port)
{
	TCPData*	TData;
	int		i;

	if (Port->Seqs->num_pieces == TCP_QUEUE_SIZE)
		return FALSE;

	GetDataByID(PacketSlot, IPDecoderID, (void**)&TData);
	if (!TData) {
		PrintPacketSummary(stderr, PacketSlot, NULL, TData, false);
		PRINTERROR("This was supposed to be a TCP packet\n");
		return FALSE;
	}

	// new packet fits exactly after first bunch of packets in buffer
	if (TData->Header->seq == Port->Seqs.LastSeq + 1) {
		if (Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1 >= TCP_CACHE_SIZE) {
			PRINTPKTERROR(NULL, NULL, TData, false);
			PRINTERROR("out of space in TCP cache\n");
			return FALSE;
		}
		memcpy(TData->Data, 
		       &(Port->Seqs.buffer) + (Port->Seqs.LastSeq - Port->Seqs.TopSeq), 
		       TData->DataLen);
		// finds position for the packet in pieces[]
		for (i = 0; Port->Seqs.pieces[i].piece_end < Port->Seqs.LastSeq; i++);
		if (i + 1 == TCP_QUEUE_SIZE) {
			PRINTERROR("pieces[] out of space?\n");
			return FALSE;
		}
		// move other pieces[] forward, to make space
		if (i < TCP_QUEUE_SIZE - 1)
			memmove(&(Port->Seqs.pieces[i+1]), &(Port->Seqs.pieces[i]), 
				size_of(struct tcp_piece)*(TCP_QUEUE_SIZE-i));
		Port->Seqs.pieces[i].piece_start = TData->Header->seq;
		Port->Seqs.pieces[i].piece_end = TData->Header->seq + TData->DataLen-1;
		Port->Seqs.pieces[i].PacketSlot = PacketSlot;
		Port->Seqs.num_pieces++;
		Port->Seqs.LastSeq = TData->Header->seq + TData->DataLen - 1;

		// try to add queued packets to the buffer
		// try multiple times, because after a packet is popped out,
		// maybe there's room for another one
		roda_testes_no_buffer();
		TODO! delete first queue entry, unblocking the packet;
		while (TCPStream_Unqueue(Port)) {
		       roda_testes_no_buffer();
		       delete first entry again & unblock the packet;
		}
	} else {
		// This packet doesn't follow the previous one. So we queue it
		DBG(PRINTPKTERROR(NULL, NULL, TData, false));
		DBG(PRINTERROR2("packet doesn't follows previous one (LastSeq:%d this packet's seq:%d)\n", Port->Seqs.LastSeq, TData->Header->seq));
		if (Port->Seqs.queue_size < TCP_QUEUE_SIZE) 
			Port->Seqs.queue[i++] = PacketSlot;
		BlockPacket(PacketSlot);
	}

	return TRUE;
}

/**
 * Try to add to the TCP buffer packets previously queued
 * @see RemountTCPStream
 * @return TRUE if a packet is unqueued
 */
int TCPStream_Unqueue(PP* Port)
{
	TCPData*	TData;
	int i;

	for (i = 0; i < Port->Seqs.num_pieces; i++)
		// put this piece after the others
		if (Port->Seqs.pieces[i].piece_start == 
		    Port->Seqs.LastSeq + 1) {
			GetDataBtID(Port->Seqs.pieces[i].PacketSlot,
				    IPDecodedID, (void**)&TData);
			if (!TData) {
				PRINTPKTERROR(Port->Seqs.pieces[i].PacketSlot, NULL, TData, false);
				PRINTERROR("Error reading TCP data (while unqueuing TCP stream buffer\n");
				return FALSE;
			}
			if (TData->DataLen > (TCP_CACHE_SIZE - Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1))
				// buffer can't hold the packet!
				// then just wait for another time...
				return FALSE;
			memcpy(&(Port->Seqs.buffer) + Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1,
			       TData->Data, TData->DataLen);
			// unqueue it
			/*
			  TODO! should unqueue only after checking the rules
			  in the buffer, because otherwise we don't know
			  the PacketSlot to unblock it...
			memmove(&(Port->Seqs.pieces[i]), 
				&(Port->Seqs.pieces[i+1]),
				(Port->Seqs.num_pieces-- - i - 1) * sizeof(struct tcp_stream_piece));
			*/
			return TRUE;
			
		// put this piece before the others
		} else if (Port->Seqs.pieces[i].piece_end ==
			   Port->Seqs.TopSeq - 1) {
			GetDataBtID(Port->Seqs.pieces[i].PacketSlot,
				    IPDecodedID, (void**)&TData);
			if (!TData) {
				PRINTPKTERROR(Port->Seqs.pieces[i].PacketSlot, NULL, TData, false);
				PRINTERROR("Error reading TCP data (while unqueuing TCP stream buffer\n");
				return FALSE;
			}
			// buffer can't hold the packet!
			// then just wait for another time...
			if (TData->DataLen > (TCP_CACHE_SIZE - Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1))
			1~	return FALSE;
			// first, move down the buffer to make space...
			memmove(&(Port->Seqs.buffer) + TData->DataLen,
				&(Port->Seqs.buffer),
				Port->Seqs.LastSeq - Port->Seqs.TopSeq + 1);
			memcpy(&(Port->Seqs.buffer), TData->Data, TData->DataLen);
	
			// unqueue it
			/* TODO (see above)
			memmove(&(Port->Seqs.pieces[i]), 
				&(Port->Seqs.pieces[i+1]),
				(Port->Seqs.num_pieces-- - i - 1) * sizeof(struct tcp_stream_piece));
			*/
			return TRUE;
		} else if (
			((TData->Header->seq < Port->Seqs.pieces[i].piece_end) &&
			 (TData->Header->seq > Port->Seqs.pieces[i].piece_start)) ||
			((Port->Seqs.pieces[i].piece_start > TData->Header->seq) &&
			 (Port->Seqs.pieces[i].piece_start < TData->Header->seq + TData->DataLen - 1)) ) {
			// packet boundaries overwrite! drop the packet
			drop_packet();
		}
	return FALSE;
}

#endif	// TCP_STREAM
