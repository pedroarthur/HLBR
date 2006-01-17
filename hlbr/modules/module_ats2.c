#include "module_ats2.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../engine/session.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

//#define DEBUG
//#define DEBUG1
//#define DEBUG2

int					ATS2ModuleID;
extern GlobalVars	Globals;

MessageItem*	ATS2FName;
char			ATS2Filename[1024];

/*put this in the config*/
#define ATS2_LOG_ROTATE_INTERVAL	60*60

FILE*			ATS2fp;
int				ATS2LastRotate;
unsigned int	ATS2ID;

void LogATS2(PP* Session, void* Data);

/*******************************************
* Set some values on the module
*******************************************/
int ModuleATS2ParseArg (char* Arg){
#ifdef DEBUGPATH
	printf("In ModuleATS2ParseArg\n");
#endif

	if (strncmp(Arg, "filename=",9)==0){
		ATS2FName=ParseMessageString(Arg+9);
		ApplyMessage(ATS2FName, 0, ATS2Filename, 1024);
		printf("Setting filename to %s\n", ATS2Filename);
		ATS2fp=fopen(ATS2Filename, "a");
		if (!ATS2fp){
			printf("Couldn't open %s for appending\n",ATS2Filename);
			return FALSE;
		}
		
		if (!AddSessionDestroyHandler(LogATS2, NULL)){
			printf("Couldn't hook session handler\n");
			return FALSE;
		}
	
		return TRUE;
	}else{
		printf("ATS2:Unknown Option %s\n",Arg);
		return FALSE;	
	}

	return FALSE;
}

/****************************************
* Check to see if we need to rotate the
* log file
****************************************/
void RotateLogFile(int now){
#ifdef DEBUGPATH
	printf("In RotateLogFile\n");
#endif

	//if ((ATS2LastRotate>0) && ((now-ATS2LastRotate)<ATS2_LOG_ROTATE_INTERVAL)) return;
	if ((ATS2LastRotate>0) && ((now/60)==(ATS2LastRotate/60))) return;
	
//#ifdef DEBUG
	printf("Log needs to be rotated\n");
//#endif	

	ApplyMessage(ATS2FName, 0, ATS2Filename, 1024);	
	printf("Setting filename to %s\n", ATS2Filename);
	fclose(ATS2fp);
	ATS2fp=fopen(ATS2Filename, "a");
	if (!ATS2fp){
		printf("Couldn't open %s for appending\n",ATS2Filename);
		return;
	}
	ATS2LastRotate=now;
}

/***************************************
* Write a log entry out to disk
* Logging in human readable form for now
***************************************/
void LogATS2(PP* Session, void* Data){
	struct tm*	tm;
#ifdef DEBUGPATH
	printf("In LogATS2\n");
#endif

	fprintf(ATS2fp, "%08i ",Session->SessionID);
	tm=localtime(&Session->FirstTime);					
	fprintf(ATS2fp, "%02i/%02i/%04i %02i:%02i:%02i",
		tm->tm_mon+1, 
		tm->tm_mday+1,
		tm->tm_year+1900,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec);
	tm=localtime(&Session->LastTime);
	fprintf(ATS2fp, "-%02i:%02i:%02i ",
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec);
	fprintf(ATS2fp, "%s:%u", inet_ntoa(*(struct in_addr*)&Session->Parent->IP1), Session->Port1);
	switch (Session->Direction){
	case SESSION_IP2_SERVER:
		fprintf(ATS2fp, "->");
		break;
	case SESSION_IP1_SERVER:
		fprintf(ATS2fp, "<-");
		break;
	default:
		fprintf(ATS2fp, "??");
	}
	fprintf(ATS2fp, "%s:%u  -  ",inet_ntoa(*(struct in_addr*)&Session->Parent->IP2),Session->Port2);
	fprintf(ATS2fp, "T%u U%u I%u O%u\n",Session->TCPCount, Session->UDPCount, Session->ICMPCount, Session->OtherCount);
	
	RotateLogFile(Session->LastTime);
}

/**************************************
* Log everything when we shut down
**************************************/
int ATS2ShutdownFunc(void* Data){
	
#ifdef DEBUGPATH
	printf("In ATS2ShutdownFunc\n");
#endif

	if (Globals.Modules[ATS2ModuleID].Active==FALSE){
#ifdef DEBUG	
		printf("ATS2 module isn't active\n");
#endif
		return TRUE;
	}
	
	if (ATS2fp) fclose(ATS2fp);
	
	printf("Done\n");

	return TRUE;
}

/**************************************
* Set up the ATS2 logger
**************************************/
int InitModuleATS2(){
	int	ModuleID;
	
#ifdef DEBUGPATH
	printf("In InitModuleATS2\n");
#endif

	ModuleID=CreateModule("ATS2");
	if(ModuleID==MODULE_NONE) return FALSE;
	
	Globals.Modules[ModuleID].ParseArg=ModuleATS2ParseArg;
	Globals.Modules[ModuleID].ModuleFunc=NULL;
	
	/*we need to log everything during shutdown*/
	ATS2ModuleID=ModuleID;
	AddShutdownHandler(ATS2ShutdownFunc, NULL);
		
	ATS2LastRotate=0;
	ATS2ID=0;
	
	return TRUE;
}

