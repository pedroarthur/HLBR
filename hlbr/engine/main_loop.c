/*******************************************
* How the main loop works depends on 
* threads and other factors.
*******************************************/
#include "main_loop.h"
#include "hlbrlib.h"
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
#define DEBUGPATH ;
//#define DEBUGPACKETS
//#define DEBUG1

extern GlobalVars	Globals;
extern int			TCPDecoderID;
extern int			UDPDecoderID;


/**
 * Idle function. Called whenever hlbr is idle
 */
void IdleFunc()
{
	DEBUGPATH;

#ifdef DEBUGPACKETS
	PRINTERROR("There are:\n");
	PRINTERROR1("  %i Idle\n",	Globals.IdleCount);
	PRINTERROR1("  %i Pending\n",	Globals.PendingCount);
	PRINTERROR1("  %i Saved\n",	Globals.SavedCount);
	PRINTERROR1("  %i Allocated\n",	Globals.AllocatedCount);
	PRINTERROR1("  %i Processing\n",Globals.ProcessingCount);
#endif
#ifdef _OBSD_	
 	usleep(100);
#else
	usleep(100);
#endif
}


/**
 * Apply the routing and send out the packet.
 */
int RouteAndSend(int PacketSlot)
{
	PacketRec*	p;
	
	DEBUGPATH;
	
	p = &Globals.Packets[PacketSlot];
	
	/* No routing Protocols */
	if (Globals.NumRoutes == 0)
		return TRUE;
	/* dropped by rules */
	if (!p->PassRawPacket)
		return TRUE;
	
	p->TargetInterface = -1;
	
#ifdef DEBUG1	
	if (p->InterfaceNum == 2)
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
	
	if (!Route(PacketSlot)) {
		DBG( PRINTERROR("Routing rules dropped the packet\n") );
		return TRUE;
	}

	if (p->TargetInterface == -1) {
		DBG( PRINTERROR("No Packet Handler set a route. Dropping.\n") );
		return FALSE;
	}

#ifdef DEBUG1
	if (p->InterfaceNum == 2)
	printf("- Sending packet out interface %i(%s)\n",p->TargetInterface, Globals.Interfaces[p->TargetInterface].Name);
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

	DEBUGPATH;

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

/**
 * Check the packet for rules matches.
 * This is one of the main functions responsible for everything HLBR does;
 * the other is Decode(), called here. Decode() is called with the 'root'
 * packet decoder, so all registered decoders (TCP, UDP, etc.) will 
 * be called, with all their respective registered tests (according to the
 * rules defined by the user). After this, the RuleBits field of the packet 
 * structure is tested to see if any rule matched, and the necessary actions
 * performed. Then finally the packet is 'routed' and sent.
 * @return Always TRUE?
 * @remarks Basically this is what ProcessPacket does:
 * @li Calls HandleTimers()
 * @li Calls the 'root' decoder (defined in Globals.DecoderRoot) with Decode()
 * @li Tests the RuleBits packet field (results of the tests/rules); if any rule matched, calls PerformActions()
 * @li Then, the packet is routed with RouteAndSend()
 */
int ProcessPacket(int PacketSlot)
{
	PacketRec*	p;
	static int	PacketSec=0;
	static int	TCPSec=0;
	static int	UDPSec=0;
	static int	LastTime=0;
	void*		data;
	
	DEBUGPATH;

	if (Globals.PacketLimit == 0) {
		PRINTERROR("Packet Limit Reached\n");
		Globals.Done = TRUE;
	}
	
	if (Globals.PacketLimit > 0)
		Globals.PacketLimit--;

	p = &Globals.Packets[PacketSlot];

	DBG( PRINTERROR1("P:%u\n", p->PacketNum) );

	if (p->tv.tv_sec)
		HandleTimers(p->tv.tv_sec);

	if (!Decode(Globals.DecoderRoot,PacketSlot)) {
		PRINTERROR("Error applying decoder to packet\n");
	}

	/* update the packet statistics */
	PacketSec++;
	if (GetDataByID(PacketSlot, TCPDecoderID, &data)) {
		TCPSec++;
		// Unblock first packet from TCP remount buffer
		TCPRemount_unblock(PacketSlot, FALSE);
	} else if (GetDataByID(PacketSlot, UDPDecoderID, &data))
		UDPSec++;
		
	if (Globals.Packets[PacketSlot].tv.tv_sec != LastTime) {
		Globals.PacketsPerSec = PacketSec;
		Globals.TCPPerSec = TCPSec;
		Globals.UDPPerSec = UDPSec;
	
		//printf("%i packet, %i tcp, %i udp %i other\n",PacketSec, TCPSec, UDPSec, PacketSec-(TCPSec+UDPSec));	
		
		PacketSec = 0;
		TCPSec = 0;
		UDPSec = 0;
		LastTime = Globals.Packets[PacketSlot].tv.tv_sec;
	}

		
	if (!BitFieldIsEmpty(p->RuleBits,Globals.NumRules)) {
		DBG( PRINTERROR("There are rule matches\n") );
		if (!PerformActions(PacketSlot)) {
			PRINTERROR("Failed to execute the actions\n");
		}
	}

	// route the packet only if it isn't blocked by TCP stream remount
	if (p->Status != PACKET_STATUS_BLOCKED) {
		RouteAndSend(PacketSlot);
		ReturnEmptyPacket(PacketSlot);
	}

	return TRUE;
}


/**
* Thread to process packets from the queue.
* There may be more than one of these (but not currently in HLBR).
*/
void* ProcessPacketThread(void* v)
{
	int	PacketSlot;
	
	DEBUGPATH;

	while (!Globals.Done){
		PacketSlot = PopFromPending();		
		if (PacketSlot != PACKET_NONE) {
			ProcessPacket(PacketSlot);
		} else {
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
	
	DEBUGPATH;

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

/**
 * Spawn a thread for each interface.
 */
int MainLoopThreaded()
{
	int i;
//	pthread_t	test_thread;
	
	DEBUGPATH;

	Globals.Done = FALSE;
	
	/* start up the interface threads */
	for (i=0;i<Globals.NumInterfaces;i++)
		if (!StartInterfaceThread(i)){
			printf("Couldn't start thread for interface\n");
			return FALSE;
		}
#ifdef DEBUG
		else
			printf("Starting thread for interface %i\n", i);
#endif
	
	/*start up the first process packet thread*/
	//pthread_create(&test_thread, NULL, ProcessPacketThread, NULL);
	ProcessPacketThread(NULL);

	return FALSE;
}

/**
 * Main loop, start handling packets. Calls one of the two other functions:
 * MainLoopThreaded() if HLBR is running in multi-thread mode, or 
 * MainLoopPolling(), if in single-thread mode.
 * @return Always FALSE?
 */
int MainLoop()
{
	int i;
	
	DEBUGPATH;

	if (!Globals.UseThreads) {
		for (i = 0; i < Globals.NumInterfaces; i++) {
			if (!Globals.Interfaces[i].IsPollable) {
				PRINTERROR("All interfaces must be able to poll in single thread mode.\n");
				return FALSE;
			}
		}
		return MainLoopPoll();
	} else {
		return MainLoopThreaded();
	}
	
	return FALSE;
}
