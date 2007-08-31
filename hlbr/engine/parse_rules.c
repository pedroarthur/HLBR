#include "parse_rules.h"
#include "parse_config.h"
#include "hlbrlib.h"
#include "../decoders/decode.h"
#include "../actions/action.h"
#include <string.h>
#include "message.h"
#include <stdlib.h>

extern GlobalVars Globals;

//#define DEBUG

int ParseDecoderLine(char* DecoderLine, int RuleNum);


/***********************************
* Set the action on a rule
***********************************/
int SetAction(int RuleID, char* ActionName){
	int i;

	DEBUGPATH;

	for (i=0;i<Globals.NumActions;i++){
		if (strcasecmp(ActionName, Globals.Actions[i].Name)==0){
			return i;
		}
	}

	return ACTION_NONE;
}

/***********************************
* Make sense out of this rule
***********************************/
int ParseRule(FILE* fp){
	char		LineBuff[10240];
	int			RuleNum;
	char		ActionSet;
	char		MessageSet;
	char		DefaultRule[256];
	int			GID;
	int			Revision;

	DEBUGPATH;

	RuleNum=Globals.NumRules;
	snprintf(DefaultRule, MAX_MESSAGE_LEN, "Rule %i\n",RuleNum);
	GID=USER_RULE_START+RuleNum;
	Revision=1;

	ActionSet=FALSE;
	MessageSet=FALSE;
	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</rule>")==0){
#ifdef DEBUG
			printf("All done with this rule\n");
#endif
			if (!ActionSet){
				printf("Warning: Action defaults to drop for rule %d\n", RuleNum);
			}
			if (!MessageSet){
				printf("Warning: Message defaults to \"%s\"\n", DefaultRule);
				Globals.Rules[RuleNum].MessageFormat=ParseMessageString(DefaultRule);
			}

			Globals.NumRules++;
			return TRUE;
		}else if (strncasecmp(LineBuff,"action=",7)==0){
			if (ActionSet){
				printf("Warning: Action was already set to %s\n",
					Globals.Actions[Globals.Rules[RuleNum].Action].Name);
			}

			if ( (Globals.Rules[RuleNum].Action=SetAction(RuleNum, LineBuff+7))!=ACTION_NONE){
				ActionSet=TRUE;
#ifdef DEBUG
			printf("Setting Action %s\n",Globals.Actions[Globals.Rules[RuleNum].Action].Name);
#endif
			}

			if (!ActionSet){
				printf("Error: Couldn't find action %s\n",LineBuff+7);
				return FALSE;
			}
		}else if (strncasecmp(LineBuff, "message=",	8)==0){
#ifdef DEBUG
			printf("Setting Message To \"%s\"\n",LineBuff+8);
#endif
			if (MessageSet){
				printf("Warning: Message was already set\n");
			}

			Globals.Rules[RuleNum].MessageFormat=ParseMessageString(LineBuff+8);
			MessageSet=TRUE;
		}else if (strncasecmp(LineBuff, "GID=",	4)==0){
			Globals.Rules[RuleNum].GlobalID=atoi(LineBuff+4);
#ifdef DEBUG
			printf("Setting GID To %i\n",Globals.Rules[RuleNum].GlobalID);
#endif
		}else if (strncasecmp(LineBuff, "rev=",	4)==0){
			Globals.Rules[RuleNum].Revision=atoi(LineBuff+4);
#ifdef DEBUG
			printf("Setting Rev To %i\n",Globals.Rules[RuleNum].Revision);
#endif
		}else{
			if (!ParseDecoderLine(LineBuff, RuleNum)){
				printf("Warning: Couldn't understand rule option: %s\n",LineBuff);
			}else{
			}
		}
	}

	return FALSE;
}


/***********************************************
* Add a line in a rule to the decoder/test
***********************************************/
int ParseDecoderLine(char* DecoderLine, int RuleNum){
	char		Line[10240];
	int		DecoderID;
	char*		DecoderName;
	char*		TestName;
	char*		Args;
	char*		Delim;
	DecoderRec*	Decoder;
	TestRec*	Test;

	DEBUGPATH;

	/*parse the line*/
	snprintf(Line, 10240, "%s",DecoderLine);
	DecoderName=Line;
	Delim=strchr(Line, ' ');
	if (!Delim){
		printf("Warning: Invalid line %s\n",Line);
		return FALSE;
	}

	*Delim=0x00;
	TestName=Delim+1;

	/*find that decoder*/
#ifdef DEBUG
	printf("Decoder Name is %s\n",DecoderName);
#endif

	DecoderID=GetDecoderByName(DecoderName);
	if (DecoderID==DECODER_NONE){
		printf("There is no decoder %s\n", DecoderName);
		return FALSE;
	}
	Decoder=&Globals.Decoders[DecoderID];

	/*find the test in that decoder*/
	if (!Decoder->Tests){
		printf("There are no known tests for decoder %s\n", Decoder->Name);
		return FALSE;
	}

	Delim=strchr(TestName, '(');
	if (!Delim){
		printf("Error: Expected (\n");
		return FALSE;
	}else{
		*Delim=0x00;
		Args=Delim+1;
	}

	Delim = &Args[strlen(Args)-1];
	if (*Delim != ')') {
		printf("Error: Expected )\n");
		return FALSE;
	}else{
		*Delim=0x00;
	}

	Test=Decoder->Tests;
	while (Test){
		if (
			(strcasecmp(TestName, Test->Name)==0) ||
			(strcasecmp(TestName, Test->ShortName)==0)
		){
#ifdef DEBUG
			printf("Found test %s\n",TestName);
#endif
			if (Test->AddNode) return Test->AddNode(Test->ID, RuleNum, Args);
			return FALSE;
		}
		Test=Test->Next;
	}

	printf("Warning: There is no test \"%s\" for decoder \"%s\"\n",TestName, DecoderName);
	return FALSE;
}


/***********************************
* Make sense out of the rules file
***********************************/
int ParseRules(char* FName){
	FILE*		fp;
	char		LineBuff[10240];
	char*		End;
	char*		Start;
	char		Name[512];
	char		FDir[512];
	int			i;

	DEBUGPATH;

#ifdef DEBUG
	printf("About to parse rule file %s\n", FName);
#endif



	fp=fopen(FName, "r");
	if (!fp){
		//Extract path of Rules file...
		strcpy(FDir, Globals.RulesFilename);
		for (i = strlen(FDir); i >= 0 && FDir[i] != '/'; i--);
    	FDir[i+1] = 0;
		strcat(FDir, FName);
		fp=fopen(FDir, "r");
		if (!fp){
			snprintf(Name, 512, "rules/%s", FName);
			fp=fopen(Name, "r");
			if (!fp){
				printf("Couldn't open rules file %s\n",FName);
				return FALSE;
			}
		}
	}

	while (GetLine(fp, LineBuff, 10240)){
		if (strncasecmp(LineBuff, "<rule>",6)==0){
			/*Process the system options*/
			if (!ParseRule(fp)) return FALSE;
		}else if(strncasecmp(LineBuff, "<include",8)==0){
			Start=LineBuff+8;
			while (*Start==' ') Start++;
			if (*Start=='>'){
				printf("Error parsing %s\nFormat <include FILENAME>\n",LineBuff);
				return FALSE;
			}
			End=strchr(LineBuff+8,'>');
			if (!End){
				printf("Expected \">\"\n");
				return FALSE;
			}
			*End=0x00;
			if (!ParseRules(Start)) return FALSE;
	}
	}

	fclose(fp);

	return TRUE;
}
