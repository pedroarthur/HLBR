#include "action_alert_file.h"
#include <stdio.h>
#include "../engine/message.h"
#include <stdlib.h>
#include <string.h>

//#define DEBUG

typedef struct action_file_rec{
	char		fname[1024];
} ActionFileRec;

extern GlobalVars	Globals;

FILE*	fp;

/******************************************
* Parse the args for this action
******************************************/
void* AlertFileParseArgs(char* Args){
	FILE*			fp;
	ActionFileRec*	data;
	char			FileName[1024];
#ifdef DEBUGPATH
	printf("In AlertFileParseArgs\n");
#endif

#ifdef DEBUG
	printf("Parsing args for action_alert_file\n");
#endif	

	snprintf(FileName,1024,"%s%s",Globals.LogDir, Args);
	fp=fopen(FileName, "a");
	if (!fp){
		printf("Couldn't open file \"%s\" for appending\n", FileName);
		return NULL;
	}
	fclose(fp);

	data=(ActionFileRec*)calloc(sizeof(ActionFileRec),1);
	snprintf(data->fname, 1024, "%s", FileName);

	return data;
}


/******************************************
* handle informational messages
******************************************/
int AlertFileMessage(char* Message, void* Data){
	FILE*			fp;
	ActionFileRec*	data;
	
#ifdef DEBUGPATH
	printf("In AlsertFileMessage\n");
#endif

#ifdef DEBUG
	printf("Writing to the Alert File\n");
#endif

	if (!Data){
#ifdef DEBUG
		printf("I must have a filename to write to\n");
#endif	
		return FALSE;
	}
	
	data=(ActionFileRec*)Data;

	fp=fopen(data->fname, "a");
	if (!fp){
#ifdef DEBUG	
		printf("Couldn't open \"%s\" for writing\n",data->fname);
#endif		
		return FALSE;
	}

	fwrite(Message, strlen(Message), 1, fp);
	fwrite("\n", 1, 1, fp);
	
	fclose(fp);
	
	return TRUE;
}

/******************************************
* write the alert message to the alert file
******************************************/
int AlertFileAction(int RuleNum, int PacketSlot, void* Data){
	char	Buff[1024];
	FILE*			fp;
	ActionFileRec*	data;
	PacketRec*		p;
	
#ifdef DEBUGPATH
	printf("In AlsertFileAction\n");
#endif

#ifdef DEBUG
	printf("Writing to the Alert File\n");
#endif

	if (!Data){
#ifdef DEBUG
		printf("I must have a filename to write to\n");
#endif	
		return FALSE;
	}
	
	
	p=&Globals.Packets[PacketSlot];
	data=(ActionFileRec*)Data;

	fp=fopen(data->fname, "a");
	if (!fp){
#ifdef DEBUG	
		printf("Couldn't open \"%s\" for writing\n",data->fname);
#endif		
		return FALSE;
	}

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, 1024)){
		printf("Couldn't alert header to packet\n");
		return FALSE;
	}

	fwrite(Buff, strlen(Buff), 1, fp);
	fwrite(" ", 1, 1, fp);


	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	fwrite(Buff, strlen(Buff), 1, fp);
	fwrite("\n", 1, 1, fp);
	
	fclose(fp);
	
	return TRUE;
}

/********************************
* Set up the alert file stuff
********************************/
int InitActionAlertFile(){
	int ActionID;

#ifdef DEBUGPATH
	printf("In InitActionAlertFile\n");
#endif

	ActionID=CreateAction("alert file");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action alert file\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=AlertFileAction;
	Globals.ActionItems[ActionID].MessageFunc=AlertFileMessage;
	Globals.ActionItems[ActionID].ParseArgs=AlertFileParseArgs;

	return TRUE;
}
