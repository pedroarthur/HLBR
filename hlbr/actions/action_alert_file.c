#include "action_alert_file.h"
#include <stdio.h>
#include "../engine/message.h"
#include "../engine/hlbr.h"
#include <stdlib.h>
#include <string.h>


//#define DEBUG

extern GlobalVars	Globals;

/**
 * Parse the args for this action (alert file).
 */
void* AlertFileParseArgs(char* Args)
{
	FILE*		fp;

	LogFileRec*	data;
	char		FileName[1024];

	DEBUGPATH;

	snprintf(FileName,1024,"%s%s",Globals.LogDir, Args);
	fp = fopen(FileName, "a");
	if (!fp) {
		PRINTERROR1("Couldn't open file \"%s\" for appending\n", FileName);
		return NULL;
	}
	fclose(fp);

	data = (LogFileRec*)calloc(sizeof(LogFileRec), 1);
	snprintf(data->fname, 1024, "%s", FileName);

	return data;
}


/**
 * Handle the message (write to a log file).
 * Basically it gets a file name (inside the LogFileRec type) and writes 
 * the message to it.
 */
int AlertFileMessage(char* Message, void* Data)
{
	LogFileRec*	data;
	FILE*		fp;
#ifdef MTHREADS
	int		ocs;
#endif
	
	DEBUGPATH;

	if (!Data) {
		PRINTERROR("I must have a filename to write to!\n");
		return FALSE;
	}

	data = (LogFileRec*)Data;

#ifdef MTHREADS
	hlbr_mutex_lock (&data->FileMutex, 0, &data->FileLockID);
#endif
	//fp = LogFile(data);
	fp = fopen(data->fname, "a");

	if (!fp) {
#ifdef MTHREADS
		hlbr_mutex_unlock (&data->FileMutex);
#endif
		return FALSE;
	}

#ifdef MTHREADS
	pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &ocs);
#endif

	fwrite(Message, strlen(Message), 1, fp);
	fwrite("\n", 1, 1, data->fp);

#ifdef MTHREADS
	pthread_setcancelstate (ocs, NULL);
#endif

	//CloseLogFile(data);
	fclose(fp);
#ifdef MTHREADS
	hlbr_mutex_unlock (&data->FileMutex);
#endif

	return TRUE;
}

/**
 * Write the alert message to the alert file (action alert file).
 */
int AlertFileAction(int RuleNum, int PacketSlot, void* Data)
{
	char		Buffa[1024];
	char		Buffb[1024];
	FILE*		fp;
	LogFileRec*	data;
	PacketRec*	p;
#ifdef MTHREADS
	int		ocs;
#endif

	DEBUGPATH;

	if (!Data) {
		PRINTERROR("AlertFileAction: Must have a filename to write to!\n");
		return FALSE;
	}

	p = &Globals.Packets[PacketSlot];
	data = (LogFileRec*)Data;

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buffa, 1024)) {
		PRINTERROR("AlertFileAction: Couldn't alert header to packet\n");
		return FALSE;
	}

	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buffb, 1024)) {
		PRINTERROR("AlertFileAction: Couldn't apply message to packet\n");
		return FALSE;
	}

#ifdef MTHREADS
	hlbr_mutex_lock (&data->FileMutex, 0, &data->FileLockID);
#endif
	//fp = LogFile(data);
	fp = fopen(data->fname, "a");

	if (!fp) {
		PRINTERROR1("AlertFileAction: Couldn't open \"%s\" for writing\n",data->fname);
#ifdef MTHREADS
		hlbr_mutex_unlock (&data->FileMutex);
#endif
		return FALSE;
	}

#ifdef MTHREADS
	pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &ocs);
#endif
	fwrite(Buffa, strlen(Buffa), 1, fp);
	fwrite(" ", 1, 1, fp);

	fwrite(Buffb, strlen(Buffb), 1, fp);
	fwrite("\n", 1, 1, fp);
#ifdef MTHREADS
	pthread_setcancelstate (ocs, NULL);
#endif

	//CloseLogFile(data);
	fclose(fp);
#ifdef MTHREADS
	hlbr_mutex_unlock (&data->FileMutex);
#endif
	return TRUE;
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
		PRINTERROR("InitActionAlertFile: Couldn't allocate action alert file\n");
		return FALSE;
	}

	Globals.ActionItems[ActionID].ActionFunc = AlertFileAction;
	Globals.ActionItems[ActionID].MessageFunc = AlertFileMessage;
	Globals.ActionItems[ActionID].ParseArgs = AlertFileParseArgs;

	return TRUE;
}
