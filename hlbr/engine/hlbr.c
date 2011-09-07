//#define DEBUG
//#define DEBUGLOCKS

#include "hlbr.h"
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
#include <errno.h>
#include <pwd.h>

/** @mainpage HLBR Code Documentation
 * This is the documentation for HLBR's code, generated with Doxygen.\n
 * HLBR code can be quite a bit hard to grasp at first glance; 
 * if you want a place to start, I'd suggest you take a look at the 
 * ProcessPacket() and Decode() functions.
 */

GlobalVars Globals;

int CallShutdownHandlers();

/**************************************
* Create a new timer
***************************************/
int CreateTimer(char* Name, unsigned int Interval, int (*TimerFunc)(int TimerID, int Time, void* User), void* User){
	int	TimerID;

	if (!TimerFunc)
		return TIMER_NONE;
	if (!Name)
		return TIMER_NONE;
	if (Interval==0)
		return TIMER_NONE;

	for ( TimerID = 0 ; TimerID < MAX_TIMERS ; TimerID++)
		if (Globals.Timers[TimerID].InUse==FALSE)
			break;

	if (TimerID == MAX_TIMERS)
		return TIMER_NONE;

	Globals.Timers[TimerID].InUse = TRUE;
	snprintf(Globals.Timers[TimerID].Name, MAX_NAME_LEN, "%s", Name);
	Globals.Timers[TimerID].Interval = Interval;
	Globals.Timers[TimerID].LastTime = 0;
	Globals.Timers[TimerID].User = User;
	Globals.Timers[TimerID].TimerFunc = TimerFunc;

	return TimerID;
}


/**
 * Prints out the version number.
 */
void PrintVersion() 
{
	printf("\n\nHogwash Light BR (HLBR) v%i.%i.%i\n", MAJOR_VERSION, MINOR_VERSION, CODE_REVISION);
	printf("http://hlbr.sourceforge.net\n\n");
	printf("(based on Jason Larsen's Hogwash)\n\n\n");
}

/**
 * Tell the user about the command line.
 */
void PrintUsage()
{
	DEBUGPATH;

	PrintVersion();

	printf("HLBR eh um IPS brasileiro e alguns arquivos possuem frases em portugues e ingles.\n");
	printf("HLBR is a Brazilian IPS and some files has phrases in portuguese and english.\n\n\n");
	printf("Utilizacao / Usage:\n");
	printf("------------------\n");
	printf("hlbr <args>\n");
	printf("  -c  <Arquivo de configuracao / Config file>\n");
	printf("  -r  <Arquivo de regras / Rules file>\n");
	printf("  -l  <Diretorio de log / Log directory>\n");
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
}

/**
 * Detach this process (runs in daemon mode).
 */
int hlbr_daemon(int nochdir, int noclose)
{
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
#else
	switch (fork()){
		case -1:
			printf("fork() failed\n");
			exit(1);
		case 0:
			break;
		default:
			exit(0);
	}

	if (setsid() == -1)
		exit(0);

	if (!noclose && (fd=open("/dev/null", O_RDWR, 0))!=-1){
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);

		if (fd>2)
			close(fd);
	}
#endif
	return TRUE;
}

/**
 * Make sense out of the command line.
 * Parse the parameters received by the main() function.
 */
int ParseArgs(int argc, char **argv)
{
	int c;

	DEBUGPATH;

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
		if (c == -1)
			break;

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
				hlbr_daemon(0,0);
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

/**
 * Handle POSIX signals.
 */
void HandleSignal(int signal)
{
	int i;

	DEBUGPATH;

	switch (signal) {
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			printf("Signal %i recieved. Shutting down pid %i\n", signal, getpid());

			for (i = 0 ; i < Globals.DThreadsNum ; i++) {
				pthread_cancel (Globals.DThreads[i]);
			}

			for (i = 0 ; i < Globals.NumInterfaces ; i++) {
				if (Globals.Interfaces[i].RxThreadID)
					pthread_cancel (Globals.Interfaces[i].RxThreadID);

				if (Globals.Interfaces[i].TxThreadID)
					pthread_cancel (Globals.Interfaces[i].TxThreadID);
			}

			for (i = 0 ; i < Globals.AThreadsNum ; i++) {
				pthread_cancel (Globals.AThreads[i]);
			}

			if (remove(Globals.PidFilename) != 0)
				fprintf(stderr, "Could not delete Pid file: %s\n", Globals.PidFilename);

			Globals.Done = TRUE;

			break;
	}
}

/**
 * The One and Only main
*/
int main(int argc, char**argv)
{
	bzero(&Globals, sizeof(GlobalVars));

	Globals.PacketLimit=-1;

	if (argc==1){
		PrintUsage();
		return FALSE;
	}

#ifdef LOGFILE_THREAD
	InitLogFiles();	/* before parsing config file */
#endif

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

	if (Globals.ParseOnly)
		return TRUE;

	if (!OpenInterfaces()){
		printf("Error initializing interfaces\n");
		return FALSE;
	}

	if (!DropRootPrivileges()){
		printf("Error dropping root privileges\n");
		return FALSE;
	}	

	/*start up the signal handlers*/
	signal(SIGINT, HandleSignal);
	signal(SIGQUIT, HandleSignal);
	signal(SIGTERM, HandleSignal);
	signal(SIGPIPE, SIG_IGN);

	MainLoop();

	printf("HLBR is all done.  Calling shutdown handlers\n");
	CallShutdownHandlers();

	return 0;
}

/**************************************
* Put this somewhere else later
***************************************/
int GetListByName(char* Name){
	int	i;

	DEBUGPATH;

	for (i = 0 ; i < Globals.NumLists ; i++){
		if (strcasecmp(Globals.Lists[i].Name, Name)==0)
			return i;
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

	f = calloc(sizeof(FuncList), 1);
	f->Func = func;
	f->Data = data;

	if (!Globals.ShutdownFuncs){
		Globals.ShutdownFuncs = f;
		return TRUE;
	}else{
		this=Globals.ShutdownFuncs;

		while (this->Next)
			this=this->Next;

		this->Next=f;

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

	this=Globals.ShutdownFuncs;

	while (this){
		if (!this->Func(this->Data)){
			printf("Shutdown handler failed\n");
		}

		this=this->Next;
	}

	return TRUE;
}

/****************************************
* Drop privilegies 
****************************************/
int DropRootPrivileges() {
	
	if (getuid() != 0) 
		return TRUE;

	if (Globals.Uid == 0) {
		return FALSE;
	}

	if (Globals.Gid != 0) {
		if (setgid(Globals.Gid) != 0) {
			perror("Privileges dropping error");
			return FALSE;
		}
	} else {
		struct passwd *pwd;
		if ((pwd=getpwuid(Globals.Uid)) != NULL) {
			Globals.Gid = (int) pwd->pw_gid;
			if (setgid(Globals.Gid) != 0)
				return FALSE;
		} else {
			return FALSE;
		}	
	}
	
	char *piddir = FindLastDirInPath(Globals.PidFilename, "/");

	if(chown(piddir, Globals.Uid, Globals.Gid) != 0){
		perror("PID diretory privileges dropping error");
		free(piddir);
		return FALSE;
	}
	free(piddir);

	if(chown(Globals.PidFilename, Globals.Uid, Globals.Gid) != 0){
		perror("PID file privileges dropping error");
		return FALSE;
	}

	if (setuid(Globals.Uid) != 0) {
		perror("Privileges dropping error");
		return FALSE;
	} else
		return TRUE;
}

#ifdef DEBUG
#undef DEBUG
#endif
#ifdef DEBUGLOCKS
#undef DEBUGLOCKS
#endif
