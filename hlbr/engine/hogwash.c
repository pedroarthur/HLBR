#include "hogwash.h"
#include "parse_config.h"
#include "parse_rules.h"
#include "main_loop.h"
#include "session.h"
#include "../decoders/decode.h"
#include "../tests/test.h"
#include "../packets/packet.h"
#include "../packets/packet_cache.h"
#include "../actions/action.h"
#include "../routes/route.h"
#include "../modules/module.h"
#include "../mangle/mangle.h"
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

//#define DEBUGPATH
#define DEBUG
#define DEBUGLOCKS

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


/**************************************
* print out the version number
***************************************/
void PrintVersion() {
	printf("Hogwash H2 v%i.%i\n", MAJOR_VERSION, MINOR_VERSION);
	printf("by Jason Larsen\n\n");
}

/*************************************
* Tell the user about the command line
**************************************/
void PrintUsage(){

#ifdef DEBUGPATH
	printf("In PrintUsage\n");
#endif
	PrintVersion();

	printf("Usage:\n");
	printf("------------------\n");
	printf("hogwash <args>\n");
	printf("  -c  <Config File>\n");
	printf("  -r  <Rules File>\n");
	printf("  -l  <Log Directory>\n");
	printf("  -t  Parse Rules and Exit\n");
	printf("  -n  Process n packets and exit\n");
	printf("  -d  Enter Daemon Mode (Background Execution)\n");
	printf("  -v  Print version and exit\n");
}

/******************************************
* Detach this process
******************************************/
int hogwash_daemon(int nochdir, int noclose){
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

/***********************************
* Make sense of the command line
************************************/
int ParseArgs(int argc, char **argv){
	int 	c;
	
#ifdef DEBUGPATH
	printf("In ParseArgs\n");
#endif

#define HOG_PARSEARGS_FLAGS "c:r:tn:l:dhv"

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
			if (Globals.LogDir[strlen(Globals.LogDir)-1]!='/'){
				Globals.LogDir[strlen(Globals.LogDir)]='/';
			}
			printf("Log directory is %s\n",Globals.LogDir);			
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
			hogwash_daemon(0,0);
			break;
		case 'h':
			PrintUsage();
			exit(0);
		case 'v':
			PrintVersion();
			exit(0);
		default:
			printf("Unknown option\n");	
		}	
	}

	if (!Globals.LogDir){
		Globals.LogDir=calloc(5,1);
	}

	return TRUE;
}

/**************************************************
* Abstract away the thread locking for 
* ease of programming
**************************************************/
int hogwash_mutex_lock(pthread_mutex_t*	mutex, int ID, int* LockID){
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
int hogwash_mutex_trylock(pthread_mutex_t* mutex, int ID, int* LockID){
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
int hogwash_mutex_unlock(pthread_mutex_t*	mutex){
#ifndef HAS_THREADS
	return TRUE;
#else
	if (!Globals.UseThreads) return TRUE;
	return pthread_mutex_unlock(mutex);
#endif
}

/*************************************
* Handle the signals
*************************************/
void HandleSignal(int signal){
#ifdef DEBUGPATH
	printf("In HandleSignal\n");
#endif

	switch (signal){
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

	if (argc==1){
		PrintUsage();
		return FALSE;
	}	
	
	if (!ParseArgs(argc, argv)){
		printf("Couldn't understand command line, quitting\n\n");
		PrintUsage();
		return FALSE;
	}

	if (!InitDecoders()){
		printf("Error initializing decoders\n");
		return FALSE;
	}

	if (!InitTests()){
		printf("Error initializing tests\n");
		return FALSE;
	}

	if (!InitActions()){
		printf("Error initializing actions\n");
		return FALSE;
	}

	if (!InitSession()){
		printf("Error initializing session tracker\n");
		return FALSE;
	}
		
	if (!InitRoutes()){
		printf("Error initializing route handlers\n");
		return FALSE;
	}

	if (!InitModules()){
		printf("Error initializing modules\n");
		return FALSE;
	}

	if (!InitManglers()){
		printf("Error initializing manglers\n");
		return FALSE;
	}

	if (!ParseConfig()){
		printf("Error loading config file\n");
		return FALSE;
	}

	if (!ParseRules(Globals.RulesFilename)){
		printf("Error loading rules file\n");
		return FALSE;
	}
	printf("Loaded %i rules\n",Globals.NumRules);

	if (!TestsFinishSetup()){
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

	MainLoop();

	printf("Hogwash is all done.  Calling shutdown handlers\n");
	CallShutdownHandlers();

	return TRUE;
}

/**************************************
* Put this somewhere else later
***************************************/
int GetListByName(char* Name){
	int	i;
#ifdef DEBUGPATH
	printf("In GetListByName\n");
#endif

	for (i=0;i<Globals.NumLists;i++){
		if (strcasecmp(Globals.Lists[i].Name, Name)==0) return i;
	}
	
	return LIST_NONE;

}

/*****************************************
* Add a function to be called during
* shutdown
****************************************/
int AddShutdownHandler(int (*func)(void* data), void* data){
	FuncList*	f;
	FuncList*	this;
	
#ifdef DEBUGPATH
	printf("In AddShutdownHandler\n");
#endif

	f=calloc(sizeof(FuncList),1);
	f->Func=func;
	f->Data=data;

	if (!Globals.ShutdownFuncs){
		Globals.ShutdownFuncs=f;
		return TRUE;
	}else{
		this=Globals.ShutdownFuncs;
		while (this->Next) this=this->Next;
		this->Next=f;
		return TRUE;
	}
}

/****************************************
* Let everything shutdown gracefully
****************************************/
int CallShutdownHandlers(){
	FuncList*	this;
	
#ifdef DEBUGPATH
	printf("In CallShutdownHandlers\n");
#endif

	this=Globals.ShutdownFuncs;
	while (this){
		if (!this->Func(this->Data)){
			printf("Shutdown handler failed\n");
		}
		this=this->Next;
	}
	
	return TRUE;
}
