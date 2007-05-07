/** @mainpage HLBR Code Documentation
 * This is the documentation for HLBR's code, generated with Doxygen.\n
 * HLBR code can be quite a bit hard to grasp at first glance; 
 * if you want a place to start, I'd suggest you take a look at the 
 * ProcessPacket() and Decode() functions.
 */

#include "hlbr.h"
#include "hlbrlib.h"
#include "parse_config.h"
#include "parse_rules.h"
#include "main_loop.h"
#include "session.h"
#include "../decoders/decode.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include "../tests/test.h"
#include "../packets/packet.h"
#include "../packets/packet_cache.h"
#include "../actions/action.h"
#include "../routes/route.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#ifdef _LINUX_
#include <getopt.h>
#endif
#ifdef _SOLARIS_
#include <strings.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define DEBUGPATH ;
//#define DEBUG
//#define DEBUGLOCKS

GlobalVars Globals;

int CallShutdownHandlers();

/**************************************
* Create a new timer
***************************************/
int CreateTimer(char* Name, unsigned int Interval, int (*TimerFunc)(int TimerID, int Time, void* User), void* User){
	int	TimerID;

	if (!TimerFunc) return TIMER_NONE;
	if (!Name) return TIMER_NONE;
	if (Interval==0) return TIMER_NONE;

	for (TimerID=0;TimerID<MAX_TIMERS;TimerID++){
		if (Globals.Timers[TimerID].InUse==FALSE) break;
	}
	
	if (TimerID==MAX_TIMERS) return TIMER_NONE;

	Globals.Timers[TimerID].InUse=TRUE;
	snprintf(Globals.Timers[TimerID].Name, MAX_NAME_LEN, "%s", Name);
	Globals.Timers[TimerID].Interval=Interval;
	Globals.Timers[TimerID].LastTime=0;
	Globals.Timers[TimerID].User=User;
	Globals.Timers[TimerID].TimerFunc=TimerFunc;

	return TimerID;
}


/**
 * Print out the version number.
 */
void PrintVersion()
{
	printf("\nHogwash Light BR (HLBR) v%i.%i\n", MAJOR_VERSION, MINOR_VERSION);
//	printf("by Andre Bertelli Araujo and\n   Joao Eriberto Mota Filho\n\n");
	printf("http://hlbr.sourceforge.net\n");
	printf("(based in Jason Larsen's Hogwash)\n");
}

/**
 * Tell the user about the command line.
 */
void PrintUsage(char op)
{
	DEBUGPATH;

	PrintVersion();

	switch (op) {
	case 0:
		printf("Utilizacao / Usage:\n");
		printf("------------------\n");
		printf("hlbr <args>\n");
		printf("  -c  <Arquivo de configuracao / Config file>\n");
		printf("  -r  <Arquivo de regras / Rules file>\n");
		printf("  -l  <Diretorio de log / Log directory>\n");
		printf("  -L  <Opcoes de log / Log options> (-L help)\n");
		printf("  -t  Analisa regras e sai / Parse rules and exit\n");
		printf("  -n  Processa n pacotes e sai / Process n packets and exit\n");
		printf("  -d  Executa em modo daemon / Enter Daemon Mode (Background Execution)\n");
		printf("  -v  Mostra versao e sai / Print version and exit\n");
		printf("------------------\n");
		printf("Exemplo / Example:\n");
		printf("  hlbr -c hlbr.config -r hlbr.rules &\n");
		printf("------------------\n");
		printf("Os arquivos de configuracao e regras estao em /etc/hlbr/.\n");
		printf("The configuration files and rules are in /etc/hlbr/.\n\n\n");	
		break;
	case 1:
		printf("Opcoes para a chave -L / Options for -L flag\n");
		printf("  s  Loga inicio e fim de sessao TCP / Logs start and end of a TCP session\n");
		printf("  S  Loga todos os detalhes sobre uma sessao TCP (gera MUITA saida)\n     Logs all details about a TCP session (generates TOO MUCH output)\n");
		printf("Ex: hlbr -L s\n");
		break;
	}
}

/******************************************
* Detach this process
******************************************/
int hlbr_daemon(int nochdir, int noclose){
	int fd;

	printf("Entering Daemon Mode\n");
#ifdef HAS_FREOPEN
	if (!noclose) {
		freopen("/dev/null", "r", stdin);
		freopen("/dev/null", "w", stdout);
		freopen("/dev/null", "w", stderr);
	}
#endif
	if (!nochdir)
		chdir("/");

#ifdef HAS_DAEMON
	if ((fd = daemon(1,1)) == (-1)) {
		printf("Failed to enter daemon mode\n");
		exit(1);
	}
#else	/* !HAS_DAEMON */
	switch (fork()){
	case -1:
		printf("fork() failed\n");
		exit(1);
	case 0:
		break;
	default:
		exit(0);
	}
	
	if (setsid() == -1) exit(0);
	if (!noclose && (fd=open("/dev/null", O_RDWR, 0))!=-1){
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd>2) close(fd);
	}
#endif	/* HAS_DAEMON */

	return TRUE;
}

/**
 * Make sense of the command line.
 * Parse the parameters received by the main() function
 */
int ParseArgs(int argc, char **argv)
{
	int 	c;
	char* 	l;
	
	DEBUGPATH;

#define HOG_PARSEARGS_FLAGS "c:r:tn:l:dhvL:"

	while (1) {
#ifndef HAS_OPT_LONG
		c = getopt(argc, argv, HOG_PARSEARGS_FLAGS);
#else
		int option_index = 0;
		static struct option long_options[] = {
			{"config", 1, 0, 'c'},
			{"rules", 1, 0, 'r'},
			{"test", 0, 0, 't'},
			{"number", 1, 0, 'n'},
			{"log", 1, 0, 'l'},				   
			{"daemon", 0, 0, 'd'},
			{"help", 0, 0, 'h'},
			{"version", 0, 0, 'v'},
			{"log-options", 1, 0, 'L'},
			{0, 0, 0, 0}
		};

		c = getopt_long (argc, argv, HOG_PARSEARGS_FLAGS,
                        long_options, &option_index);
#endif						
		if (c == -1) break;

		switch (c) {
		case 'c':
			printf("Config file is %s\n",optarg);

			Globals.ConfigFilename=(char*)calloc(strlen(optarg)+1,sizeof(char));
			memcpy(Globals.ConfigFilename, optarg, strlen(optarg));
			break;
		case 'l':
			Globals.LogDir=(char*)calloc(strlen(optarg)+2,sizeof(char));
			memcpy(Globals.LogDir, optarg, strlen(optarg));
			if (Globals.LogDir[strlen(Globals.LogDir)-1] != '/') {
				Globals.LogDir[strlen(Globals.LogDir)] = '/';
			}
			PRINT1("Log directory is %s\n", Globals.LogDir);
			break;			
		case 'L':
			if ((!optarg) || (strncmp("help", optarg, 4) == 0)) {
				PrintUsage(1);
				exit(0);
			}
			l = optarg;
			while (*l)
				switch (*(l++)) {
				case 's':
					PRINT("Logging sessions: start and end of sessions\n");
					Globals.logSession_StartEnd = 1;
					break;
				case 'S':
					PRINT("Logging sessions: all details\n");
					Globals.logSession_All = 1;
					break;
				default:
					PrintUsage(1);
					exit(0);
				}
			break;	
		case 'r':
			printf("Rules file is %s\n",optarg);

			Globals.RulesFilename=(char*)calloc(strlen(optarg)+1,sizeof(char));
			memcpy(Globals.RulesFilename, optarg, strlen(optarg));			
			break;	
		case 't':
			Globals.ParseOnly=TRUE;
			break;
		case 'n':
			Globals.PacketLimit=atoi(optarg);
			break;
		case 'd':
			hlbr_daemon(0,0);
			break;
		case 'h':
			PrintUsage(0);
			exit(0);
		case 'v':
			PrintVersion();
			exit(0);
		default:
			printf("Unknown option\n");	
		}	
	}

	if (!Globals.LogDir) {
		Globals.LogDir = calloc(5,1);
	}
	if (Globals.logSession_StartEnd || Globals.logSession_All) {
		snprintf(Globals.logSessionFile.fname, 1024, "%s%s", 
			 Globals.LogDir, "sessions.log");
		PRINT1("Sessions log file is %s\n", Globals.logSessionFile.fname);
	}


	return TRUE;
}

/**************************************************
* Abstract away the thread locking for 
* ease of programming
**************************************************/
int hlbr_mutex_lock(pthread_mutex_t*	mutex, int ID, int* LockID){
#ifndef HAS_THREADS
	return TRUE;
#else
	int	result;
	
	if (!Globals.UseThreads) return TRUE;	
	result = pthread_mutex_lock(mutex);
#ifdef DEBUGLOCKS	
	*LockID=ID;
#endif	
	return result;
#endif
}

/**************************************************
* Abstract away the thread locking for 
* ease of programming
**************************************************/
int hlbr_mutex_trylock(pthread_mutex_t* mutex, int ID, int* LockID){
#ifndef HAS_THREADS
	return TRUE;
#else
	int result;
	
	if (!Globals.UseThreads) return TRUE;
	result = pthread_mutex_trylock(mutex);
#ifdef DEBUGLOCKS	
	*LockID=ID;
#endif	
	return result;
#endif
}

/**************************************************
* Abstract away the thread locking for 
* ease of programming
**************************************************/
int hlbr_mutex_unlock(pthread_mutex_t*	mutex){
#ifndef HAS_THREADS
	return TRUE;
#else
	if (!Globals.UseThreads) return TRUE;
	return pthread_mutex_unlock(mutex);
#endif
}

/**
 * Handle the signals (POSIX signals)
 */
void HandleSignal(int signal)
{
	DEBUGPATH;

	switch (signal) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		printf("Signal %i recieved. Shutting down pid %i\n", signal, getpid());	
		Globals.Done=TRUE;
		break;
	}
}

/*************************************
* The one and only main
**************************************/
int main(int argc, char**argv){

	bzero(&Globals, sizeof(GlobalVars));
	Globals.IdleCount=MAX_PACKETS;
	Globals.PacketLimit=-1;

	if (argc==1) {
		PrintUsage(0);
		return FALSE;
	}	
	
	if (!ParseArgs(argc, argv)){
		printf("Couldn't understand command line, quitting\n\n");
		PrintUsage(0);
		return FALSE;
	}

	if (!InitDecoders()) {
		printf("Error initializing decoders\n");
		return FALSE;
	}

	if (!InitTests()) {
		printf("Error initializing tests\n");
		return FALSE;
	}

	if (!InitActions()) {
		printf("Error initializing actions\n");
		return FALSE;
	}

	if (!InitSession()) {
		printf("Error initializing session tracker\n");
		return FALSE;
	}
		
	if (!InitRoutes()) {
		printf("Error initializing route handlers\n");
		return FALSE;
	}

	if (!ParseConfig()) {
		printf("Error loading config file\n");
		return FALSE;
	}

	if (!ParseRules(Globals.RulesFilename)) {
		printf("Error loading rules file\n");
		return FALSE;
	}
	printf("Loaded %i rules\n",Globals.NumRules);

	if (!TestsFinishSetup()) {
		printf("Tests failed finish setup\n");
		return FALSE;
	}

			
	if (Globals.ParseOnly) return TRUE;

	if (!OpenInterfaces()){
		printf("Error initializing interfaces\n");
		return FALSE;
	}

	/*start up the signal handlers*/
	signal(SIGINT, HandleSignal);
	signal(SIGQUIT, HandleSignal);
	signal(SIGTERM, HandleSignal);
	signal(SIGPIPE, SIG_IGN);

#ifndef HAS_THREADS
	Globals.UseThreads=FALSE;
#ifdef DEBUG
	printf("No Thread Suppport. Forcing Non-Threaded Mode.\n");
#endif	
#endif

	if (Globals.UseThreads)
		MainLoopThreaded();
	else
		MainLoop();

	printf("HLBR is all done.  Calling shutdown handlers\n");
	CallShutdownHandlers();

	return TRUE;
}

/**************************************
* Put this somewhere else later
***************************************/
int GetListByName(char* Name){
	int	i;

	DEBUGPATH;

	for (i=0;i<Globals.NumLists;i++){
		if (strcasecmp(Globals.Lists[i].Name, Name)==0) return i;
	}
	
	return LIST_NONE;

}

/**
 * Add a function to be called during shutdown.
 * Defines a callback function.
 */
int AddShutdownHandler(int (*func)(void* data), void* data)
{
	FuncList*	f;
	FuncList*	this;
	
	DEBUGPATH;

	f = calloc(sizeof(FuncList),1);
	f->Func = func;
	f->Data = data;

	if (!Globals.ShutdownFuncs) {
		Globals.ShutdownFuncs = f;
		return TRUE;
	}else{
		this = Globals.ShutdownFuncs;
		while (this->Next) this = this->Next;
		this->Next = f;
		return TRUE;
	}
}

/**
 * Let everything shutdown gracefully.
 * Calls callback functions defined for shutdown.
 */
int CallShutdownHandlers()
{
	FuncList*	this;
	
	DEBUGPATH;

	this = Globals.ShutdownFuncs;
	while (this) {
		if (!this->Func(this->Data)) {
			printf("Shutdown handler failed\n");
		}
		this = this->Next;
	}
	
	return TRUE;
}



/**
 * Prints a one-line summary of the packet.
 * Inspects packet's IP and TCP structure (if any)
 */
void PrintPacketSummary(FILE* stream, int PacketSlot, IPData* IData, TCPData* TData, char newline)
{
	if (!IData) {
		if (!TData) {
			if (PacketSlot != -1)
				fprintf(stream, "P:%u -%c", PacketSlot,
					(newline ? '\n' : ' '));
		} else 
			// No IP data but TCP data?...
			fprintf(stream, "P:%u TCP ?.?.?.?:%d->?.?.?.?:%d [%u ack:%u]%c",
		PacketSlot, ntohs(TData->Header->source), ntohs(TData->Header->dest),
		TData->Header->seq, TData->Header->ack_seq,
		(newline ? '\n' : ' '));
		return;
	}
	if (!TData) {
		if (PacketSlot != -1)
			fprintf(stream, "P:%u IP %d.%d.%d.%d->%d.%d.%d.%d%c", PacketSlot,
				IP_BYTES(IData->Header->saddr), IP_BYTES(IData->Header->daddr),
				(newline ? '\n' : ' '));
		return;
	}
	fprintf(stream, "P:%u TCP %d.%d.%d.%d:%d->%d.%d.%d.%d:%d [%u",
		PacketSlot,
		IP_BYTES(IData->Header->saddr), ntohs(TData->Header->source),
		IP_BYTES(IData->Header->daddr), ntohs(TData->Header->dest),
		TData->Header->seq);
	if (TData->Header->ack_seq)
		fprintf(stream, " ack:%u", TData->Header->ack_seq);
	if (TData->Header->syn || TData->Header->fin || TData->Header->rst) {
		putc(' ', stream);
		if (TData->Header->syn)	putc('s', stream);
		if (TData->Header->fin)	putc('f', stream);
		if (TData->Header->rst)	putc('r', stream);
	}
	putc(']', stream);
	if (newline)
		putc('\n', stream);
	return;
}

/**
 * Prints a one-line summary of the session.
 * Can be called right after PrintPacketSummary, and continue printing in the
 * same line (in this case PrintPacketSummary's newline parameter should be
 * false, of course.).
 */
void PrintSessionSummary(FILE* stream, PP* Port, char newline)
{
	fprintf(stream, "S:%d, %d packets%c", Port->SessionID, Port->TCPCount,
		(newline ? '\n' : ' '));
	
	return;
}

/**
 * Prints the TCP buffer for the session.
 * Non-printable characters are printed as dots
 */
void PrintSessionBuffer(FILE* stream, PP* Port)
{
	int i;

	fprintf(stream, "Session:%d (%d.%d.%d.%d:%d->%d.%d.%d.%d:%d)\n",
		Port->SessionID, IP_BYTES(Port->Parent->IP1), Port->Port1,
		IP_BYTES(Port->Parent->IP2), Port->Port2);
	if (Port->Stream0) {
		fprintf(stream, "\tStream0:\n");
		for (i=0; i < (Port->Stream0->LastSeq - Port->Stream0->TopSeq + 1); i++)
			putc(
				(Port->Stream0->Payloads[i] >= 32 || Port->Stream0->Payloads[i] <=127
				 ? Port->Stream0->Payloads[i] : '.'),
				stream
				);
		putc(10, stream);
	}
	if (Port->Stream1) {
		fprintf(stream, "\tStream1:\n");
		for (i=0; i < (Port->Stream1->LastSeq - Port->Stream1->TopSeq + 1); i++)
			putc(
				(Port->Stream1->Payloads[i] >= 32 || Port->Stream1->Payloads[i] <=127
				 ? Port->Stream1->Payloads[i] : '.'),
				stream
				);
		putc(10, stream);
	}
	
	return;
}
