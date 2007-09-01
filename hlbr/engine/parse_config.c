#include "../config.h"
#include "parse_config.h"
#include "../packets/packet.h"
#include "../routes/route.h"
#include "../actions/action.h"
#include "../engine/message.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

extern GlobalVars	Globals;

//#define DEBUGPATH
//#define DEBUG

/****************************************
* Get a line out of the rules file
* TODO: Make this recursive
****************************************/
int GetLine(FILE* fp, char* buff, int buff_len){
	int 	Done;
	char	LineBuff[65536];
	char*	Begin;
	char*	End;
	
	DEBUGPATH;

	bzero(buff, buff_len);
	Done=FALSE;
	while (!Done){
		if (!fgets(LineBuff, 65536, fp)) return FALSE;
		if (LineBuff[0]=='#') continue;
		
		/*erase any whitespace at the front*/
		Begin=LineBuff;
		while (((*Begin==' ') || (*Begin=='\t')) && (*Begin!='\n') && (*Begin!='\0')) Begin++;
		if (*Begin=='\0') continue;
		if (*Begin=='\n') continue;
		
		/*erase the line feed at the end*/
		End=Begin+strlen(Begin)-1;
		if (*End=='\n'){
			*End='\0';
			End--;
		}
		
		if (*End==0x09){
			*End='\0';
			End--;
		}
		
		if (*End==';'){
			*End='\0';
			End--;
		}
		
		/*if the line ends with a slash, read in the next line*/
		if (*End=='\\'){
#ifdef DEBUG1
			printf("Line ends with a continuation character\n");
#endif			
			if (!fgets(End-1, 65536, fp)) return FALSE;
					/*erase the line feed at the end*/
			End=Begin+strlen(Begin)-1;
			if (*End=='\n'){
				*End='\0';
				End--;
			}
		
			if (*End==0x09){
				*End='\0';
				End--;
			}
		
			if (*End==';'){
				*End='\0';
				End--;
			}

		}
				
		snprintf(buff, buff_len, "%s", Begin);
		return TRUE;
	}	
	
	return FALSE;
}

/***********************************
* Make sense out of this list
***********************************/
int ParseList(FILE* fp, char* Name, int ListType){
	char		LineBuff[10240];
	int 		ListID;
	GlobalList*	List;
	
	DEBUGPATH;

	if (!Name) return FALSE;	
	while (*Name==' ') Name++;

#ifdef DEBUG
	printf("Setting for list %s\n",Name);
#endif

	ListID=GetListByName(Name);
	if (ListID!=LIST_NONE){
		printf("There is already a list name \"%s\"\n",Name);
		return FALSE;
	}

	List=&Globals.Lists[Globals.NumLists];
	
	List->List=InitNumList(LIST_TYPE_NORMAL);
	snprintf(List->Name, MAX_NAME_LEN, Name);
#ifdef DEBUG
	printf("Setting list name to \"%s\"\n",List->Name);
#endif	

	while(GetLine(fp, LineBuff, 10240)){
		if (*LineBuff=='#') continue;
		if (strcasecmp(LineBuff, "</list>")==0){
#ifdef DEBUG
			printf("All done with list \"%s\"\n",List->Name);
#endif			
			Globals.NumLists++;
			return TRUE;
		}else{
			switch(ListType){
			case LIST_TYPE_IP:
				if (!AddIPRanges(List->List, LineBuff)){
					printf("I couldn't understand ip list %s\n",LineBuff);
					return FALSE;
				}
#ifdef DEBUG
				printf("Added %s to ip list %s\n",LineBuff, List->Name);
#endif				
				break;
			default:
				printf("I don't understand that list type\n");
				return FALSE;
			}
		}
	}


	return FALSE;
}


/***********************************
* Make sense out of this action
***********************************/
int ParseAction(FILE* fp, char* Name){
	char		LineBuff[10240];
	int			ActionNum;
	ActionRec*	Action;
	int			ActionItemID;
	char*		Args;
	char*		Args2;
	
	DEBUGPATH;

#ifdef DEBUG
	printf("Parsing Action\n");
#endif	

	if (!Name) return FALSE;
	
	while(*Name==' ') Name++;
	
	ActionNum=Globals.NumActions;
	Action=&Globals.Actions[ActionNum];
	
	/*set the defaults*/
	bzero(Action, sizeof(ActionRec));
	snprintf(Action->Name, MAX_NAME_LEN, "%s",Name);
	Action->ID=ActionNum;

	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</action>")==0){
#ifdef DEBUG
			printf("All done with action \"%s\"\n",Action->Name);
#endif			
			Globals.NumActions++;
			return TRUE;
		}else if (strncasecmp(LineBuff, "response=",9)==0){
#ifdef DEBUG
			printf("Adding Response %s\n",LineBuff+9);
#endif
			Args=strchr(LineBuff+9,'(');
			if (Args){
				Args2=strchr(Args, ')');
				if (!Args2){
					printf("Expected \"(\"\n");
					return FALSE;
				}
				*Args=0x00;
				Args++;
				*Args2=0x00;
			}
			
			ActionItemID=GetActionByName(LineBuff+9);
			if (ActionItemID==ACTION_NONE){
				printf("There is no response named \"%s\"\n",LineBuff+9);
				return FALSE;
			}
			
			Action->ActionItems[Action->NumItems]=ActionItemID;
			if (Globals.ActionItems[ActionItemID].ParseArgs)
			if (Args) Action->ActionItemData[Action->NumItems]=Globals.ActionItems[ActionItemID].ParseArgs(Args);
			Action->NumItems++;			
		}else{	
			printf("I don't understand %s\n",LineBuff);
		}
	}
	
	return FALSE;
}


/*******************************************
* make sense of the system options
*******************************************/
int ParseSystem(FILE* fp){
	char		LineBuff[10240];
	char*		Current;
	
	DEBUGPATH;

	/*set the defaults*/
	if (Globals.SensorName) free(Globals.SensorName);
	Globals.SensorName=(char*)calloc(strlen(DEFAULT_SENSOR_NAME)+2, sizeof(char));
	snprintf(Globals.SensorName, strlen(DEFAULT_SENSOR_NAME)+1, DEFAULT_SENSOR_NAME);
	Globals.SensorID=0;

	/*loop through the lines*/
	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</system>")==0){
#ifdef DEBUG
			printf("All Done with system options\n");
#endif		
			return TRUE;
		}else if (strncasecmp(LineBuff, "name=",5)==0){
			Current=LineBuff+strlen("name=");
			if (Globals.SensorName) free(Globals.SensorName);
			Globals.SensorName=(char*)calloc(strlen(Current)+2, sizeof(char));
			snprintf(Globals.SensorName, strlen(Current)+1, Current);
#ifdef DEBUG
			printf("Sensor Name is %s\n",Globals.SensorName);
#endif			
		}else if (strncasecmp(LineBuff, "ID=",3)==0){
			Current=LineBuff+strlen("ID=");
			Globals.SensorID=atoi(Current);
#ifdef DEBUG
			printf("Sensor ID is %i\n",Globals.SensorID);
#endif			
		}else if (strncasecmp(LineBuff, "AlertHeader=",12)==0){
			Current=LineBuff+strlen("AlertHeader=");
			Globals.AlertHeader=ParseMessageString(Current);
#ifdef DEBUG
			printf("AlertHeader set\n");
#endif			
		}else if (strncasecmp(LineBuff, "Threads=",8)==0){
			Current=LineBuff+strlen("Threads=");
			switch (*Current){
			case 'Y':
			case 'y':
			case '1':
			case 't':
			case 'T':
				Globals.UseThreads=TRUE;
				break;
			case 'n':
			case 'N':
			case '0':
			case 'f':
			case 'F':
				Globals.UseThreads=FALSE;
				break;
			default:
				printf("I don't understand thread option %c\n",*Current);
				Globals.UseThreads=TRUE;
			}
#ifdef DEBUG
			printf("UseThreads is %i\n",Globals.UseThreads);
#endif			
		}else{
			printf("Warning: Unknown System Option: %s\n",LineBuff);
		}
	}

	return FALSE;
}

/*******************************************
* make sense of the interface options
*******************************************/
int ParseInterface(FILE* fp, char* Name){
	char			LineBuff[10240];
	InterfaceRec*	Interface;
	char*			Current;
	
	DEBUGPATH;

	/*get the next free interface*/
	if (Globals.NumInterfaces==MAX_INTERFACES){
		printf("You can only have a maximum of %i interfaces\n",MAX_INTERFACES);
		return FALSE;
	}
	Interface=&Globals.Interfaces[Globals.NumInterfaces];
	Interface->ID=Globals.NumInterfaces;
	Globals.NumInterfaces++;
	
	/*set the defaults*/
	Interface->Type=PACKET_TYPE_NONE;
	Interface->MTU=1500;
	Interface->Proto=PACKET_PROTO_ETHERNET;
	Interface->FD=-1;
	snprintf(Interface->Name, MAX_INTERFACE_NAME_LEN, Name);
#ifdef DEBUG
	printf("Interface Name is %s\n",Interface->Name);
#endif			
	
	/*loop through the lines*/
	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</interface>")==0){
#ifdef DEBUG
			printf("All Done with this interface\n");
#endif		
			return TRUE;
		}else if (strncasecmp(LineBuff, "type=",5)==0){
			Current=LineBuff+strlen("type=");
			Interface->Type=GetPacketTypeByName(Current);
#ifdef DEBUG
			printf("Interface Type is %i\n",Interface->Type);
#endif			
		}else if (strncasecmp(LineBuff, "proto=",6)==0){
			Current=LineBuff+strlen("proto=");
			Interface->Proto=GetPacketProtoByName(Current);
#ifdef DEBUG
			printf("Interface Proto is %i\n",Interface->Proto);
#endif			
		}else if (strncasecmp(LineBuff, "role=",5)==0){
			Current=LineBuff+strlen("role=");
			Interface->Role=GetPacketRoleByName(Current);
#ifdef DEBUG
			printf("Interface role is %i\n",Interface->Role);
#endif			
		}else{
			printf("Warning: Unknown Interface Option: %s\n",LineBuff);
		}
	}

	return FALSE;
}

/*******************************************
* make sense of the routing options
*******************************************/
int ParseRouting(FILE* fp){
	char			LineBuff[10240];
	int				RouteID;
	char*			Pos;
	char*			Pos2;
		
	DEBUGPATH;

	/*set the defaults*/

	/*loop through the lines*/
	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</routing>")==0){
#ifdef DEBUG
			printf("All Done with routing options\n");
#endif		
			return TRUE;
		}else{
			Pos=strchr(LineBuff, '(');
			if (Pos){
				*Pos=0x00;
				Pos2=strchr(Pos+1, ')');
				if (!Pos2){
					printf("Error: Expected ) is %s\n",LineBuff);
					return FALSE;
				}
				*Pos2=0x00;
			}
			if ( (RouteID=GetRouteByName(LineBuff))==ROUTE_NONE){
				printf("ERROR: Unknown Routing Option: %s\n",LineBuff);
				return FALSE;
			}
			
			if (Pos){
				if (!RouteAdd(RouteID, Pos+1)){
					printf("Routing option \"%s\" failed\n",LineBuff);
					return FALSE;
				}
				Globals.Routes[RouteID].Active=TRUE;
			}else{
				if (!RouteAdd(RouteID, NULL)){
					printf("Routing option \"%s\" failed\n",LineBuff);
					return FALSE;
				}				
				Globals.Routes[RouteID].Active=TRUE;
			}
		}
	}

	return FALSE;
}


/*******************************************
* make sense of the config file
*******************************************/
int ParseConfig(){
	FILE*		fp;
	char		LineBuff[10240];
	char*		End;
	char*		Start;
	
	DEBUGPATH;

	/*set some defaults*/
	Globals.UseThreads=TRUE;
	
	fp=fopen(Globals.ConfigFilename, "r");
	if (!fp){
		printf("Couldn't open config file %s\n",Globals.ConfigFilename);
		return FALSE;
	}

	while (GetLine(fp, LineBuff, 10240)){

		if (strncasecmp(LineBuff, "<system>",8)==0){
			/*Process the system options*/
			if (!ParseSystem(fp)) return FALSE;
		}else if(strncasecmp(LineBuff, "<interface",10)==0){
			Start=LineBuff+10;
			while (*Start==' ') Start++;
			if (*Start=='>'){
				printf("Error parsing %s\nFormat <interface NAME>\n",LineBuff);
				return FALSE;
			}
			End=strchr(LineBuff+10,'>');
			if (!End){
				printf("Expected \">\"\n");
				return FALSE;
			}
			*End=0x00;
			if (!ParseInterface(fp, Start)) return FALSE;
		}else if (strncasecmp(LineBuff, "<routing>",11)==0){
			if (!ParseRouting(fp)) return FALSE;			
		}else if(strncasecmp(LineBuff, "<action",7)==0){
			Start=LineBuff+7;
			while (*Start==' ') Start++;
			if (*Start=='>'){
				printf("Error parsing %s\nFormat <action NAME>\n",LineBuff);
				return FALSE;
			}
			End=strchr(LineBuff+7,'>');
			if (!End){
				printf("Expected \">\"\n");
				return FALSE;
			}
			*End=0x00;
			if (!ParseAction(fp, Start)) return FALSE;									
		}else if(strncasecmp(LineBuff, "<module ",8)==0){
			Start=LineBuff+7;
			while (*Start==' ') Start++;
			if (*Start=='>'){
				printf("Error parsing %s\nFormat <module NAME>\n",LineBuff);
				return FALSE;
			}
			End=strchr(LineBuff+7,'>');
			if (!End){
				printf("Expected \">\"\n");
				return FALSE;
			}
			*End=0x00;		
		}else if(strncasecmp(LineBuff, "<iplist ",8)==0){
			Start=LineBuff+7;
			while (*Start==' ') Start++;
			if (*Start=='>'){
				printf("Error parsing %s\nFormat <iplist NAME>\n",LineBuff);
				return FALSE;
			}
			End=strchr(LineBuff+7,'>');
			if (!End){
				printf("Expected \">\"\n");
				return FALSE;
			}
			*End=0x00;		
			if (!ParseList(fp, Start, LIST_TYPE_IP)) return FALSE;			
		}else{
			printf("Unexpected section %s\n",LineBuff);
			return FALSE;
		}
	}


	return TRUE;
}
