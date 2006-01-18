/*******************************************
* How the main loop works depends on 
* threads and other factors.
*******************************************/
#include "main_loop.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "../packets/packet.h"
#include "../decoders/decode.h"
#include "../routes/route.h"
#include "../actions/action.h"
#include "bits.h"
#include <stdlib.h>
#include <string.h>

//#define DEBUG
//#define DEBUGPACKETS
//#define DEBUG1

extern GlobalVars	Globals;
extern int			TCPDecoderID;
extern int			UDPDecoderID;

/************************************
* Called whenever hlbr is idle
************************************/
void IdleFunc(){
#ifdef DEBUGPATH
	printf("In IdleFunc\n");
#endif

#ifdef DEBUGPACKETS
	printf("There are:\n");
	printf("  %i Idle\n",Globals.IdleCount);
	printf("  %i Pending\n",Globals.PendingCount);
	printf("  %i Saved\n",Globals.SavedCount);
	printf("  %i Allocated\n",Globals.AllocatedCount);
	printf("  %i Processing\n",Globals.ProcessingCount);
#endif
#ifdef _OBSD_	
 	usleep(100);
#else
	usleep(100);
#endif
}


/**********************************************
* Apply the routing and send out the packet
***********************************************/
int RouteAndSend(int PacketSlot){
	PacketRec*	p;
	
#ifdef DEBUGPATH
	printf("In RouteAndSend\n");
#endif

#ifdef DEBUG
	printf("Routing the packet\n");
#endif
	
	p=&Globals.Packets[PacketSlot];
	
	/*No routing Protocols*/
	if (Globals.NumRoutes==0) return TRUE;
	/*dropped by rules*/
	if (!p->PassRawPacket) return TRUE;
	
	p->TargetInterface=-1;
	
#ifdef DEBUG1	
	if (p->InterfaceNum==2)
	printf("Routing %02X:%02X:%02X:%02X:%02X:%02X->%02X:%02X:%02X:%02X:%02X:%02X\n",
		p->RawPacket[6],
		p->RawPacket[7],
		p->RawPacket[8],
		p->RawPacket[9],
		p->RawPacket[10],
		p->RawPacket[11],
		p->RawPacket[0],
		p->RawPacket[1],
		p->RawPacket[2],
		p->RawPacket[3],
		p->RawPacket[4],
		p->RawPacket[5]);
#endif	
	
	if (!Route(PacketSlot)){
#ifdef DEBUG	
		printf("Routing rules dropped the packet\n");
#endif		
		return TRUE;
	}

	if (p->TargetInterface==-1){
#ifdef DEBUG
		printf("No Packet Handler set a route. Dropping.\n");
#endif	
		return FALSE;
	}

#ifdef DEBUG1
	if (p->InterfaceNum==2)
	printf("Sending packet out interface %i(%s)\n",p->TargetInterface, Globals.Interfaces[p->TargetInterface].Name);
#endif	
	return WritePacket(PacketSlot);	
}

/************************************
* Handle any timers that fire
************************************/
int HandleTimers(int Now){
	int			i;
	static int	NextTimer=0;
	int			TimeLeft;
	TimerRec*	t;

#ifdef DEBUGPATH
	printf("In HandleTimers\n");
#endif	

	if ( (NextTimer!=0) && (Now<NextTimer) ) return TRUE;
		
	for (i=0;i<MAX_TIMERS;i++){
		t=&Globals.Timers[i];
		if (t->InUse && t->TimerFunc){
			if ((t->Interval+t->LastTime)<=Now){
				t->InUse=t->TimerFunc(i, Now, t->User);
				t->LastTime=Now;
			}
		}
	}

	NextTimer=-65535;
	for (i=0;i<MAX_TIMERS;i++){
		t=&Globals.Timers[i];
		if (t->InUse && t->TimerFunc){
			TimeLeft=t->Interval - (Now - t->LastTime);
			if ( TimeLeft>NextTimer) NextTimer=TimeLeft;
		}
	}
	
	if (NextTimer==-65535) NextTimer=60;
	if (NextTimer>60) NextTimer=60;
	
	NextTimer+=Now;
		
	return TRUE;	
}

/************************************
* Check the packet for rules matches
************************************/
int ProcessPacket(int PacketSlot){
	PacketRec*	p;
	static int	PacketSec=0;
	static int	TCPSec=0;
	static int	UDPSec=0;
	static int	LastTime=0;
	void*		data;
	
#ifdef DEBUGPATH
	printf("In ProcessPacket\n");
#endif


	if (Globals.PacketLimit==0){
		printf("Packet Limit Reached\n");
		Globals.Done=TRUE;
	}
	
	if (Globals.PacketLimit>0) Globals.PacketLimit--;

	p=&Globals.Packets[PacketSlot];

#ifdef DEBUG
	printf("++++++++++++++++++++++++++++++++%u\n",p->PacketNum);
#endif

	if (p->tv.tv_sec) HandleTimers(p->tv.tv_sec);

	if (!Decode(Globals.DecoderRoot,PacketSlot)){
		printf("Error Processing Packet\n");
	}

	/*update the packet statistics*/
	PacketSec++;
	if (GetDataByID(PacketSlot, TCPDecoderID, &data))
		TCPSec++;
	else if (GetDataByID(PacketSlot, UDPDecoderID, &data))
		UDPSec++;
		
	if (Globals.Packets[PacketSlot].tv.tv_sec!=LastTime){
		Globals.PacketsPerSec=PacketSec;
		Globals.TCPPerSec=TCPSec;
		Globals.UDPPerSec=UDPSec;
	
		//printf("%i packet, %i tcp, %i udp %i other\n",PacketSec, TCPSec, UDPSec, PacketSec-(TCPSec+UDPSec));	
		
		PacketSec=0;
		TCPSec=0;
		UDPSec=0;
		LastTime=Globals.Packets[PacketSlot].tv.tv_sec;
	}

	
	
	if (!BitFieldIsEmpty(p->RuleBits,Globals.NumRules)){
#ifdef DEBUG
		printf("There are rule matches\n");
#endif	
		if (!PerformActions(PacketSlot)){
			printf("Failed to execute the actions\n");
		}
	}
	
	
	RouteAndSend(PacketSlot);
	ReturnEmptyPacket(PacketSlot);
	
	return TRUE;
}

/*******************************
* Start up a thread to process 
* packets from the queue.
* There may be more than one of
* these.
*******************************/
void* ProcessPacketThread(void* v){
	int	PacketSlot;
	
#ifdef DEBUGPATH
	printf("In ProcessPacketThread\n");
#endif
	

	while (!Globals.Done){
		PacketSlot=PopFromPending();		
		if (PacketSlot!=PACKET_NONE){
			ProcessPacket(PacketSlot);
		}else{
			IdleFunc();
		}	
	}


	return NULL;
}

/*******************************
* Poll the FD's to get packets
*******************************/
int MainLoopPoll(){
	struct timeval	timeout;
	int				result;
	fd_set			set;
	int				i;
	int				highest;
	int				PacketSlot;
	
#ifdef DEBUGPATH
	printf("In MainLoopPoll\n");
#endif

#ifdef DEBUG
	printf("Starting loop in poll mode\n");
	printf("--------------------------\n");
#endif

	Globals.Done=FALSE;
	while (!Globals.Done){
		timeout.tv_sec=0;
		timeout.tv_usec=IDLE_TIMEOUT;
	
		FD_ZERO(&set);
		highest=-1;
		for (i=0;i<Globals.NumInterfaces;i++){
			FD_SET(Globals.Interfaces[i].FD, &set);
			if (Globals.Interfaces[i].FD>highest)
				highest=Globals.Interfaces[i].FD;
		}
		highest++;
			
		result = select(highest, &set, NULL, NULL, &timeout);
		if (result){
#ifdef DEBUG
			printf("A packet is waiting\n");
#endif	
			/*pull the packets off*/
			for (i=0;i<Globals.NumInterfaces;i++){
				if (FD_ISSET(Globals.Interfaces[i].FD, &set)){
#ifdef DEBUG
					printf("Reading interface %s\n",Globals.Interfaces[i].Name);
#endif				
					ReadPacket(i);
				}	
			}
			
			/*Now Process them*/
			while( (PacketSlot=PopFromPending())!=-1 ){
				if (!ProcessPacket(PacketSlot)){
					printf("Couldn't process packet\n");
				}
			}
		}else{
			//printf("Calling the idle func\n");
			IdleFunc();
		}
	
	}

	return TRUE;
}

/*******************************
* Spawn a thread for each interface
*******************************/
int MainLoopThreaded(){
	int i;
//	pthread_t	test_thread;
	
#ifdef DEBUGPATH
	printf("In MainLoopThreaded\n");
#endif

#ifdef DEBUG
	printf("Starting loop in Threaded mode\n");
#endif

	Globals.Done=FALSE;
	
	/*start up the interface threads*/
	for (i=0;i<Globals.NumInterfaces;i++)
		if (!StartInterfaceThread(i)){
			printf("Couldn't start thread for interface\n");
			return FALSE;
		}
	
	/*start up the first process packet thread*/
	//pthread_create(&test_thread, NULL, ProcessPacketThread, NULL);
	ProcessPacketThread(NULL);

	return FALSE;
}

/**************************
* Start handling packets
**************************/
int MainLoop(){
	int i;
	
#ifdef DEBUGPATH
	printf("In MainLoop\n");
#endif	

	if (!Globals.UseThreads){
		for (i=0;i<Globals.NumInterfaces;i++){
			if (!Globals.Interfaces[i].IsPollable){
				printf("Error. All interfaces must be able to poll in single thread mode.\n");
				return FALSE;
			}
		}
		return MainLoopPoll();
	}else{
		return MainLoopThreaded();
	}
	
	return FALSE;
}
