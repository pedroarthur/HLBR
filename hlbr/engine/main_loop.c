//#define DEBUG
//#define DEBUGPACKETS
//#define DEBUG1

#include "main_loop.h"
#include "logfile.h"
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

extern GlobalVars	Globals;
extern int		TCPDecoderID;
extern int		UDPDecoderID;

#ifdef MTHREADS
pthread_mutex_t		StatsMutex;
pthread_mutex_t		PLimitMutex;
#endif

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
	if (!p->PassRawPacket)
		return TRUE;

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
int ProcessPacket(int PacketSlot){
	PacketRec*	p;
	static int	PacketSec=0;
	static int	TCPSec=0;
	static int	UDPSec=0;
	static int	LastTime=0;
	void*		data;

	DEBUGPATH;

#ifdef MTHREADS
	pthread_mutex_lock (&PLimitMutex);
#endif
	if (Globals.PacketLimit == 0){
		printf("Packet Limit Reached\n");
		Globals.Done=TRUE;
	}

	if (Globals.PacketLimit > 0)
		Globals.PacketLimit--;
#ifdef MTHREADS
	pthread_mutex_unlock (&PLimitMutex);
#endif

	p=&Globals.Packets[PacketSlot];

#ifdef DEBUG
	printf("++++++++++++++++++++++++++++++++%u\n",p->PacketNum);
#endif

	if (p->tv.tv_sec)
		HandleTimers(p->tv.tv_sec);

	if (!Decode(Globals.DecoderRoot, PacketSlot)) {
		printf("Error Processing Packet\n");
	}

	if (!BitFieldIsEmpty(p->RuleBits,Globals.NumRules)) {
#ifdef DEBUG
		printf("There are rule matches\n");
#endif
		if (!PerformActions(PacketSlot)) {
			printf("Failed to execute the actions\n");
		}
	}

	RouteAndSend(PacketSlot);

	/*update the packet statistics*/
#ifdef MTHREADS
	pthread_mutex_lock (&StatsMutex);
#endif
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
#ifdef MTHREADS
	pthread_mutex_unlock (&StatsMutex);
#endif
	ReturnEmptyPacket(PacketSlot);

	return TRUE;
}

/**
 * Start up a thread to process packets from the queue.
 * There may be more than one of these.
 */
void* ProcessPacketThread(void* v)
{
	int	PacketSlot;

	DEBUGPATH;
#ifdef MTHREADS
	pthread_setspecific (Globals.ThreadsKey, v);
#endif
	while (!Globals.Done) {
		PacketSlot = PopFromPending();

		if (PacketSlot != PACKET_NONE) {
			ProcessPacket(PacketSlot);
		} else {
			IdleFunc();
		}
	}

	return NULL;
}

/** Main loop, polling version.
 * Poll the FD's to get packets
 */
int MainLoopPoll()
{
	struct timeval		timeout;
	int			result;
	fd_set			set;
	int			i;
	int			highest;
	int			PacketSlot;

	DEBUGPATH;

#ifdef DEBUG
	printf("Starting loop in poll mode\n");
	printf("--------------------------\n");
#endif

	Globals.Done=FALSE;

	while (!Globals.Done){
		timeout.tv_sec = 0;
		timeout.tv_usec = IDLE_TIMEOUT;

		FD_ZERO(&set);
		highest = -1;

		for (i = 0 ; i < Globals.NumInterfaces ; i++){
			FD_SET(Globals.Interfaces[i].FD, &set);

			if (Globals.Interfaces[i].FD > highest)
				highest = Globals.Interfaces[i].FD;
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
			while((PacketSlot=PopFromPending()) != -1){
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

/** Main loop, threaded version.
 * Spawn a thread for each interface
 */
int MainLoopThreaded()
{
	int i;

	DEBUGPATH;

#ifdef DEBUG
	printf("Starting loop in Threaded mode\n");
#endif

	Globals.Done=FALSE;

	InitPacketQueue (MAX_PACKETS);

	/* start up the interface threads */
	for (i = 0 ; i < Globals.NumInterfaces ; i++)
		if (!StartInterfaceThread(i)){
			printf("Couldn't start thread for interface\n");
			return FALSE;
		}

#ifdef LOGFILE_THREAD
	/* start up the log files keeper thread */
	pthread_create(&Globals.logThread, NULL, ProcessLogFilesThread, NULL);
#endif
#ifdef LOGFILE_THREAD_NO
	fprintf(stderr, "Thread for log file keeping won't be created because we're running in non-threaded mode.\n");
#endif

#ifdef MTHREADS
	Globals.Threads = (pthread_t *) malloc ((Globals.UseThreads) * sizeof(pthread_t));

	if (!Globals.Threads) {
		fprintf (stderr, "Couldn't allocate Threads\n");
		return FALSE;
	}

	Globals.ThreadsID = (int *) malloc ((Globals.UseThreads) * sizeof(int));

	if (!Globals.ThreadsID) {
		fprintf (stderr, "Couldn't allocate ThreadsID\n");
		return FALSE;
	}

	for (i = 0 ; i < Globals.UseThreads ; i++) {
		Globals.ThreadsID[i] = i;
		pthread_create (&Globals.Threads[i], NULL, ProcessPacketThread, (void *)&Globals.ThreadsID[i]);
	}

	for (i = 0 ; i < Globals.UseThreads ; i++)
		pthread_join (Globals.Threads[i], NULL);
#else
	ProcessPacketThread(NULL);
#endif
	return FALSE;
}

/**
 * Main loop, start handling packets. Calls one of the two other functions:
 * MainLoopThreaded() if HLBR is running in multi-thread mode, or 
 * MainLoopPolling() if in single-thread mode.
 * @return Always FALSE?
 */
int MainLoop()
{
	int i;
	
	DEBUGPATH;

	if (!Globals.UseThreads){
		for (i = 0 ; i < Globals.NumInterfaces ; i++){
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


#ifdef DEBUG
#undef DEBUG
#endif
#ifdef DEBUGPACKETS
#undef DEBUGPACKETS
#endif
#ifdef DEBUG1
#undef DEBUG1
#endif
