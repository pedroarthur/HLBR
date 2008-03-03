#include "action_alert_file.h"
#include <stdio.h>
#include "../engine/message.h"
#include <stdlib.h>
#include <string.h>

//#define DEBUG

#define KEEP_LOGFILE_OPEN

extern GlobalVars	Globals;

FILE*	fp;

/**
 * Parse the args for this action (alert file).
 */
void* AlertFileParseArgs(char* Args)
{
#ifndef KEEP_LOGFILE_OPEN
	FILE*		fp;
#endif
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
	
	DEBUGPATH;

	if (!Data) {
		PRINTERROR("I must have a filename to write to!\n");
		return FALSE;
	}
	
	data = (LogFileRec*)Data;

	fp = fopen(data->fname, "a");
	if (!LogFile(data)) {
		return FALSE;
	}

	fwrite(Message, strlen(Message), 1, data->fp);
	fwrite("\n", 1, 1, data->fp);
	
	CloseLogFile(data);
	
	return TRUE;
}

/**
 * Write the alert message to the alert file (action alert file).
 */
int AlertFileAction(int RuleNum, int PacketSlot, void* Data)
{
	char		Buff[1024];
	FILE*		fp;
	LogFileRec*	data;
	PacketRec*	p;
	
	DEBUGPATH;

	if (!Data) {
		PRINTERROR("AlertFileAction: Must have a filename to write to!\n");
		return FALSE;
	}
	
	p = &Globals.Packets[PacketSlot];
	data = (LogFileRec*)Data;

	fp = fopen(data->fname, "a");
	if (!fp) {
		PRINTERROR1("AlertFileAction: Couldn't open \"%s\" for writing\n",data->fname);
		return FALSE;
	}

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, 1024)) {
		PRINTERROR("AlertFileAction: Couldn't alert header to packet\n");
		return FALSE;
	}

	fwrite(Buff, strlen(Buff), 1, fp);
	fwrite(" ", 1, 1, fp);


	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)) {
		PRINTERROR("AlertFileAction: Couldn't apply message to packet\n");
		return FALSE;
	}

	fwrite(Buff, strlen(Buff), 1, fp);
	fwrite("\n", 1, 1, fp);
	
	fclose(fp);
	
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
