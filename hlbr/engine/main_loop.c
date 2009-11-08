//#define DEBUG
//#define DEBUGPACKETS
//#define DEBUG1

#include "main_loop.h"
#include "logfile.h"
#include "../packets/packet.h"
#include "../decoders/decode.h"
#include "../routes/route.h"
#include "../actions/action.h"
#include "bits.h"

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

extern GlobalVars	Globals;
extern int		TCPDecoderID;
extern int		UDPDecoderID;

pthread_mutex_t		StatsMutex;
pthread_mutex_t		PLimitMutex;

/**
 * Called whenever hlbr is idle. 
 * Usually called by one of the threads, when it doesn't have anything to process.
 */
void IdleFunc()
{
	DEBUGPATH;

#ifdef DEBUGPACKETS
	PrintPacketCount();
#endif

	usleep(100);
}


/**
 * Apply the routing and send out the packet.
*/
int RouteAndSend(int PacketSlot)
{
	PacketRec*	p;

	DEBUGPATH;

#ifdef DEBUG
	printf("Routing the packet\n");
#endif

	p=&Globals.Packets[PacketSlot];

	/*No routing Protocols*/
	if (Globals.NumRoutes==0)
		return TRUE;

	/*dropped by rules*/
	if (!p->PassRawPacket){
		ReturnEmptyPacket(PacketSlot);
		return TRUE;
	}

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
		ReturnEmptyPacket(PacketSlot);
		return FALSE;
	}

	if (p->TargetInterface==-1){
#ifdef DEBUG
		printf("No Packet Handler set a route. Dropping.\n");
#endif
		ReturnEmptyPacket(PacketSlot);
		return FALSE;
	}

	return SchedulePacket(PacketSlot);
}

void UpdateStats (int PacketSlot) {
	static int	PacketSec=0;
	static int	TCPSec=0;
	static int	UDPSec=0;
	static int	LastTime=0;
	void*		data;

	pthread_mutex_lock (&StatsMutex);

	PacketSec++;

	if (GetDataByID(PacketSlot, TCPDecoderID, &data))
		TCPSec++;
	else if (GetDataByID(PacketSlot, UDPDecoderID, &data))
		UDPSec++;

	if (Globals.Packets[PacketSlot].tv.tv_sec != LastTime){
		Globals.PacketsPerSec = PacketSec;
		Globals.TCPPerSec = TCPSec;
		Globals.UDPPerSec = UDPSec;

		PacketSec = 0;
		TCPSec = 0;
		UDPSec = 0;

		LastTime = Globals.Packets[PacketSlot].tv.tv_sec;
	}

	pthread_mutex_unlock (&StatsMutex);
}

/************************************
* Handle any timers that fire
************************************/
int HandleTimers(int Now){
	int		i;
	static int	NextTimer=0;
	int		TimeLeft;
	TimerRec*	t;

	DEBUGPATH;

	if ((NextTimer != 0) && (Now < NextTimer))
		return TRUE;

	for (i = 0 ; i < MAX_TIMERS ; i++){
		t=&Globals.Timers[i];

		if (t->InUse && t->TimerFunc){
			if ((t->Interval + t->LastTime) <= Now){
				t->InUse = t->TimerFunc(i, Now, t->User);
				t->LastTime = Now;
			}
		}
	}

	NextTimer=-65535;

	for (i = 0 ; i < MAX_TIMERS ; i++){
		t=&Globals.Timers[i];

		if (t->InUse && t->TimerFunc){
			TimeLeft= t->Interval - (Now - t->LastTime);

			if (TimeLeft > NextTimer)
				NextTimer = TimeLeft;
		}
	}

	if (NextTimer==-65535)
		NextTimer=60;

	if (NextTimer>60)
		NextTimer=60;

	NextTimer += Now;

	return TRUE;
}

/**
 * Start up a thread to process packets from the queue and Check the packet for rules
 * matches. This is one of the main functions responsible for everything HLBR does; the
 * other is Decode(), called here. Decode() is called with the 'root' packet decoder,
 * so all registered decoders (TCP, UDP, etc.) will be called, with all their respective
 * registered tests (according to the rules defined by the user). After this, the RuleBits
 * field of the packet structure is tested to see if any rule matched, and the necessary
 * actions performed. Then finally the packet is 'routed' and sent.
 *
 * @return Null when it's done;
 * @remarks Basically this is what ProcessPacket does:
 * @li Get a packet from the packet's queue 
 * @li Calls HandleTimers()
 * @li Calls the 'root' decoder (defined in Globals.DecoderRoot) with Decode()
 * @li Tests the RuleBits packet field (results of the tests/rules); if any rule matched, calls PerformActions()
 * @li Then, the packet is routed with RouteAndSend()
 */
/**
 * 
 * There may be more than one of these.
 */
void* ProcessPackets(void* v) {
	PacketRec*	p;
	int		PacketSlot;

	DEBUGPATH;

	pthread_setspecific (Globals.DThreadsKey, v);

	while (!Globals.Done) {
		PacketSlot = PopFromPending();

		if (PacketSlot == PACKET_NONE)
			break;

		pthread_mutex_lock (&PLimitMutex);

		if (Globals.PacketLimit == 0){
			printf("Packet Limit Reached\n");
			Globals.Done=TRUE;
		}

		if (Globals.PacketLimit > 0)
			Globals.PacketLimit--;

		pthread_mutex_unlock (&PLimitMutex);

		p=&Globals.Packets[PacketSlot];

		#ifdef DEBUG
		printf("++++++++++++++++++++++++++++++++%u\n",p->PacketNum);
		#endif

		if (p->tv.tv_sec)
			HandleTimers(p->tv.tv_sec);

		if (!Decode(Globals.DecoderRoot, PacketSlot)) {
			printf("Error Processing Packet\n");
		}

		UpdateStats (PacketSlot);

		if (!BitFieldIsEmpty(p->RuleBits,Globals.NumRules)) {
			#ifdef DEBUG
			printf("There are rule matches\n");
			#endif
			AddPacketToWaiting (PacketSlot);
		} else {
			RouteAndSend(PacketSlot);
		}

		/* And we are done with this packet */
	}

	return NULL;
}

void* ProcessActions (void* v) {
	int PacketSlot;

	DEBUGPATH;

	while (!Globals.Done) {
		PacketSlot = PopFromWaiting ();

		if (PacketSlot == PACKET_NONE)
			break;

		PerformActions (PacketSlot);
		RouteAndSend (PacketSlot);
	}

	return NULL;
}

int InitPacketProcessingThreads () {
	int i;

	/* In case we don't find a value in hlbr.conf */
	if (!Globals.DThreadsNum) {
		printf ("Number of DecodingThreads not defined.\nUsing default value: 2\n");
		Globals.DThreadsNum = 2;
	}

	Globals.DThreads = (pthread_t *) malloc ((Globals.DThreadsNum) * sizeof(pthread_t));
	
	if (!Globals.DThreads) {
		fprintf (stderr, "Couldn't allocate decoding Threads\n");
		return FALSE;
	}
	
	Globals.DThreadsID = (int *) malloc ((Globals.DThreadsNum) * sizeof(int));
	
	if (!Globals.DThreadsID) {
		fprintf (stderr, "Couldn't allocate decoding Threads ID\n");
		return FALSE;
	}
	
	for (i = 0 ; i < Globals.DThreadsNum ; i++) {
		Globals.DThreadsID[i] = i;
		
		if (pthread_create (&Globals.DThreads[i], NULL, ProcessPackets, (void *)&Globals.DThreadsID[i])) {
			fprintf(stderr, "Couldn't create packet decoding thread\n");
			return FALSE;
		}
	}
	
	return TRUE;
}

int InitActionsProcessingThreads() {
	int i;

	/* In case we don't find a value in hlbr.conf */
	if (!Globals.AThreadsNum) {
		printf ("Number of PerformingThreads not defined.\nUsing default value: 1\n");
		Globals.AThreadsNum = 1;
	}

	Globals.AThreads = (pthread_t *) malloc ((Globals.AThreadsNum) * sizeof(pthread_t));

	if (!Globals.AThreads) {
		fprintf (stderr, "Couldn't allocate Actions Processing Threads\n");
		return FALSE;
	}

	Globals.AThreadsID = (int *) malloc ((Globals.AThreadsNum) * sizeof(int));

	if (!Globals.AThreadsID) {
		fprintf (stderr, "Couldn't allocate Actions Processing Threads ID\n");
		return FALSE;
	}

	for (i = 0 ; i < Globals.AThreadsNum ; i++) {
		Globals.AThreadsID[i] = i;

		if (pthread_create (&Globals.AThreads[i], NULL, ProcessActions, (void *)&Globals.AThreadsID[i])) {
			fprintf (stderr, "Couldn't create actions processing thread\n");
			return FALSE;
		}
	}

	return TRUE;
}

int InitInterfacesThreads() {
	int i;

	for (i = 0 ; i < Globals.NumInterfaces ; i++){
		if (!StartInterfaceThread(i)){
			printf("Couldn't start thread for interface\n");
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Main loop, start handling packets.
 * @return Always FALSE?
 */
int MainLoop()
{
	int i;
	sigset_t set;

	DEBUGPATH;

#ifdef DEBUG
	printf("Starting loop in Threaded mode\n");
#endif

	/*
		Won't let an arbitrary thread get signals.
		Only this thread will do it. We will let
		the signal inheritance do the job.
	*/
	sigemptyset(&set);

	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);

	i = pthread_sigmask(SIG_BLOCK, &set, NULL);

	if (i) {
		fprintf (stderr, "Can't set the thread's signal mask");
		return FALSE;
	}

	Globals.Done=FALSE;

	InitPacketQueue (MAX_PACKETS);

	if (!InitInterfacesThreads()) {
		return FALSE;
	}

#ifdef LOGFILE_THREAD
	/* start up the log files keeper thread */
	pthread_create(&Globals.logThread, NULL, ProcessLogFilesThread, NULL);
#endif

#ifdef LOGFILE_THREAD_NO
	fprintf(stderr, "Thread for log file keeping won't be created because we're running in non-threaded mode.\n");
#endif

	if (!InitActionsProcessingThreads()) {
		return FALSE;
	}

	if (!InitPacketProcessingThreads()) {
		return FALSE;
	}

	/* Just to recall: this thread will handle the signals */
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);
	while (pause() != -1);

	return FALSE;
}

#ifdef DEBUG
#undef DEBUG
#endif
#ifdef DEBUGPACKETS
#undef DEBUGPACKETS
#endif
#ifdef DEBUG1
#undef DEBUG1
#endif
