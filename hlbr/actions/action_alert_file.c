//#define DEBUG

#include "action_alert_file.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../engine/logfile.h"
#include "../engine/hlbr.h"
#include <stdlib.h>
#include <string.h>

extern GlobalVars	Globals;

/**
 * Parse the args for this action (alert file).
 */
void* AlertFileParseArgs(char* Args)
{
/*
	FILE*		fp;
	LogFileRec*	data;
	char		FileName[1024];
*/
	DEBUGPATH;
/*
	snprintf(FileName, 1024, "%s%s", Globals.LogDir, Args);
	fp = fopen(FileName, "a");
	if (!fp) {
		PRINTERROR1("Couldn't open file \"%s\" for appending\n", FileName);
		return NULL;
	}
	fclose(fp);

	data = (LogFileRec*)calloc(sizeof(LogFileRec), 1);
	snprintf(data->fname, 1024, "%s", FileName);

	return data;
*/
#ifdef DEBUG
	printf("AlertFileParseArgs: received %s\n", Args);
#endif

	return (void*)OpenLogFile(Args);
}


/**
 * Handle the message (write to a log file).
 * Basically it gets a file name (inside the LogFileRec type) and writes 
 * the message to it.
 */
int AlertFileMessage(char* Message, void* Data)
{
	int buf;
	
	//r = LogMessage(Message, Data);
	buf = GetLogBuffer();
	if (buf == LOGBUFFER_NOBUFFER)
		fprintf(stderr, "In AlertFileMessage: Could not log a message to a logfile! Message: %s\n", Message);
	strncpy(LogBuffer(buf), Message, MAX_LOGBUFFER_SIZE);
	return FlushLogBuffer(buf, (int)Data);

/*
	LogFileRec*	data;
	FILE*		fp;
#ifdef MTHREADS
	int		ocs;
#endif
	
	DEBUGPATH;

	if (!Data) {
		fprintf(stderr, "I must have a filename to write to!\n");
		return FALSE;
	}

	data = OpenLogFile((LogFileRec*)Data);

#ifdef MTHREADS
	pthread_mutex_lock (&data->FileMutex);
#endif
	//fp = LogFile(data);
	//fp = fopen(data->fname, "a");

	//if (!fp) {
#ifdef MTHREADS
	//	pthread_mutex_unlock (&data->FileMutex);
#endif
	//	return FALSE;
	//}

#ifdef MTHREADS
	pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &ocs);
#endif

	//fwrite(Message, strlen(Message), 1, fp);
	//fwrite("\n", 1, 1, data->fp);
	LogMessage(Message, data);

#ifdef MTHREADS
	pthread_setcancelstate (ocs, NULL);
#endif

	CloseLogFile(data);
	//fclose(fp);
#ifdef MTHREADS
	pthread_mutex_unlock (&data->FileMutex);
#endif

	return TRUE;
*/
}

/**
 * Write the alert message to the alert file (action alert file).
 */
int AlertFileAction(int RuleNum, int PacketSlot, void* Data)
{
	//char		Buffa[1024];
	//char		Buffb[1024];
	//char		Buff[2048];
	char*		Buff;
	int		b, len;
	FILE*		fp;
	//LogFileRec*	data;
	PacketRec*	p;
#ifdef MTHREADS
	int		ocs;
#endif

	DEBUGPATH;

	if ((int)Data == LOGFILE_NOFILE) {
		fprintf(stderr, "AlertFileAction: Must have a log file to write to!\n");
		return FALSE;
	}

	p = &Globals.Packets[PacketSlot];
	//data = (LogFileRec*)Data;
	//data = OpenLogFile((LogFileRec*)Data);
#ifdef DEBUG
	printf("AlertFileAction: message to logfile %d\n", Data);
#endif

	b = GetLogBuffer();
	if (b == LOGBUFFER_NOBUFFER) {
		fprintf(stderr, "AlertFileAction: Couldn't get log buffer to write to\n");
		return FALSE;
	}
	Buff = LogBuffer(b);

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, MAX_LOGBUFFER_SIZE/2)) {
		fprintf(stderr, "AlertFileAction: Couldn't alert header to packet\n");
		return FALSE;
	}
	len = strlen(Buff);
	Buff[len] = ' ';
	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, &Buff[len+1], MAX_LOGBUFFER_SIZE/2)) {
		fprintf(stderr, "AlertFileAction: Couldn't apply message to packet\n");
		return FALSE;
	}
/*
#ifdef MTHREADS
	pthread_mutex_lock (&data->FileMutex);
#endif
	//fp = LogFile(data);
	//fp = fopen(data->fname, "a");

	//if (!fp) {
	//	fprintf(stderr, "AlertFileAction: Couldn't open \"%s\" for writing\n", data->fname);
#ifdef MTHREADS
	//	pthread_mutex_unlock (&data->FileMutex);
#endif
	//	return FALSE;
	//}

#ifdef MTHREADS
	pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &ocs);
#endif

	//fwrite(Buff, strlen(Buff), 1, fp);
	fwrite(" ", 1, 1, fp);

	fwrite(Buffb, strlen(Buffb), 1, fp); 
	//fwrite("\n", 1, 1, fp);
	//fflush(fp);
	//LogMessage(Buff, (LogFileRec*)Data);

#ifdef MTHREADS
	pthread_setcancelstate (ocs, NULL);
#endif

	//CloseLogFile(data);
	//fclose(fp);

#ifdef MTHREADS
	pthread_mutex_unlock (&data->FileMutex);
#endif
*/
	return FlushLogBuffer(b, (int)Data);
}

/**
 * Set up the alert file stuff.
 */
int InitActionAlertFile()
{
	int ActionID;

	DEBUGPATH;

	ActionID = CreateAction("alert file");
	if (ActionID == ACTION_NONE) {
		fprintf(stderr, "InitActionAlertFile: Couldn't allocate action alert file\n");
		return FALSE;
	}

	Globals.ActionItems[ActionID].ActionFunc = AlertFileAction;
	Globals.ActionItems[ActionID].MessageFunc = AlertFileMessage;
	Globals.ActionItems[ActionID].ParseArgs = AlertFileParseArgs;

	return TRUE;
}


#ifdef DEBUG
#undef DEBUG
#endif
