#include "parse_rules.h"
#include "parse_config.h"
#include "parse_snort.h"
#include "hlbrlib.h"
#include "../decoders/decode.h"
#include "../actions/action.h"
#include <string.h>
#include "message.h"
#include <stdlib.h>
#ifdef HAS_MYSQL
#include <mysql/mysql.h>
#endif

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
		
	Delim=strchr(Args, ')');
	if (!Delim){
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
* Pull some rules from a MYSQL database
***********************************/
int RetrieveRuleMysql(char* DBase, char* User, char* Pass, char* Host){
#ifndef HAS_MYSQL
	printf("There is no MYSQL support\n");
	return FALSE;
#else
	MYSQL			sql;
	char			query[1024];
	MYSQL_RES*		res;
	MYSQL_ROW		row;
	
	MYSQL_RES*		res2;
	MYSQL_ROW		row2;
	
	char			DecoderLine[512];
	int			RuleNum;

	DEBUGPATH;
	
	mysql_init(&sql);
	if (!mysql_real_connect(&sql, Host, User, Pass, DBase, 0, NULL, 0)){
		printf("Failed to connect to database\n");
		return FALSE;
	}
	
		
	snprintf(query, 1024, "SELECT ID, GID, Revision, Action, Message from %s",
		RULES_MYSQL_TABLENAME);
	if (mysql_real_query(&sql, query, strlen(query))){
		printf("Query failed \"%s\"\n",query);
		return FALSE;
	}
	
	res=mysql_store_result(&sql);
	RuleNum=Globals.NumRules;
	while ( (row=mysql_fetch_row(res)) ){
#ifdef DEBUG
		printf("Rule %s\nGID %s\nRev %s\nAction %s\nMessage %s\n---------\n",
			row[0],
			row[1],
			row[2],
			row[3],
			row[4]
		);
#endif
		Globals.Rules[RuleNum].GlobalID=atoi(row[0]);
		Globals.Rules[RuleNum].Revision=atoi(row[1]);
		if ( (Globals.Rules[RuleNum].Action=SetAction(RuleNum, row[3]))==ACTION_NONE){
			printf("There is no action \"%s\"\n",row[3]);
			return FALSE;
		}
		Globals.Rules[RuleNum].MessageFormat=ParseMessageString(row[4]);

		/*now add all the tests to the rule*/
		snprintf(query, 1024, "SELECT Decoder, Test, Args from tests where RuleID=%s", row[0]);
		if (mysql_real_query(&sql, query, strlen(query))){
			printf("Query failed \"%s\"\n",query);
			return FALSE;
		}
	
		res2=mysql_store_result(&sql);
		while ( (row2=mysql_fetch_row(res2)) ){
#ifdef DEBUG
			printf("%s %s(%s)\n",
				row2[0],
				row2[1],
				row2[2]
			);
#endif	
			snprintf(DecoderLine, 512, "%s %s(%s)", row2[0], row2[1], row2[2]);
			if (!ParseDecoderLine(DecoderLine, RuleNum)){
				printf("Warning: Couldn't understand rule option: %s\n",DecoderLine);
			}
		}
#ifdef DEBUG		
		printf("+++++++++++++++++++\n");
#endif		
		RuleNum++;
		Globals.NumRules++;
	}


	mysql_close(&sql);
	
	return TRUE;
#endif //HAS_MYSQL
}

/****************************************/
/*  Write the rules to a MYSQL database */
/****************************************/
#if (defined(HAS_MYSQL) && 0)
int WriteMysqlRules(char* DBase, char* User, char* Pass, char* Host) {
	MYSQL			sql;
	char			query[1024];
	char			Buff[2][1024];
	// MYSQL_RES		**res;
	// MYSQL_ROW		*row;
	// char			DecoderLine[512];
	int			RuleNum;
	int			PacketSlot;
	int			BuffLen;

	DEBUGPATH;
	
	mysql_init(&sql);
	if (!mysql_real_connect(&sql, Host, User, Pass, DBase, 0, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: %s\n", mysql_error(&sql));
		return FALSE;
	}
	for (RuleNum = 0; RuleNum < Globals.NumRules; RuleNum++) {
		memset((char *) &query, 0, sizeof(query));
		memset((char *) &Buff, 0, sizeof(Buff));

		// Get the Message
		if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, 0, Buff[0], sizeof(Buff[0]))) {
			fprintf(stderr, "Couldn't apply message to packet for internal RuleNum %d\n", RuleNum);
			goto sql_errr;
		}

		// Escape the query.
		BuffLen = strlen(Buff[0]);
		if (BuffLen >= (sizeof(Buff[0]) / 2)) {
			/* 512 should be more than plenty */
			fprintf(stderr, "Message to long to format(%d/%d): %s\n", 
				BuffLen, sizeof(Buff[0]), Buff[0]);
			goto sql_errr; 
		}
		// mysql_real_escape_string(&sql, Buff[1], Buff[0], BuffLen * 2);
		mysql_real_escape_string(&sql, Buff[1], Buff[0], BuffLen);

		/* All done with Buff[0] now.. Lets use it again for the action */

		// Prepare the Action
		if (1) {

		}

		/* 
		#INSERT INTO Rules(ID, GID, Revision, Action, Message) VALUES(2, 1002, 1, 'Default', '%sip:%sp->%dip:%dp Test Rule2'); 
		#INSERT INTO tests(ID, RuleID, Decoder, Test, Args) VALUES(3, 2, 'ip', 'dst', 'WebServers');
		*/

		// Prepare the query
		snprintf(query, sizeof(query)-1, 
			"INSERT INTO %s(ID,GID,Revision,Action,Message) VALUES(%d,%d,%d,\"%s\",\"%s\")",
			RULES_MYSQL_TABLENAME,
			Globals.Rules[RuleNum].GlobalID,
			Globals.Rules[RuleNum].Revision,
			"SHOW_ME_SOME_ACTION",
			Buff[1]
		);
		// execute the query..
		if ((mysql_real_query(&sql, query, strlen(query))) != 0)
			goto sql_errr_msg;
	}
	mysql_close(&sql);
	return TRUE;

sql_errr_msg:
	fprintf(stderr, "ERROR: %s\n", mysql_error(&sql));
	goto sql_errr;

sql_errr:
	mysql_close(&sql);
	return FALSE;
}
#endif //HAS_MYSQL


/***********************************
* Pull some rules from a MYSQL database
***********************************/
int ParseRuleMysql(FILE* fp){
	char		LineBuff[10240];
	
	char 		DBase[512];
	char		User[512];
	char		Pass[512];
	char		Host[512];

	DEBUGPATH;

#ifdef DEBUG
	printf("Pulling rules from mysql database\n");
#endif
	/* made these use strncpy() as its a tad less expensive than snprintf() */
	strncpy(DBase, "hlbr5", sizeof(DBase));
	strncpy(User, "hlbr", sizeof(User));
	strncpy(Pass, "password", sizeof(Pass));
	strncpy(Host, "localhost", sizeof(Host));

	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</mysql>")==0){
#ifdef DEBUG
			printf("All done with this mysql section.  Pull the rules.\n");
#endif			
			return RetrieveRuleMysql(DBase, User, Pass, Host);
		}else if (strncasecmp(LineBuff,"dbase=",6)==0){
#ifdef DEBUG
			printf("Setting Dbase to \"%s\"\n",LineBuff+6);
#endif							
			snprintf(DBase, 512, "%s", LineBuff+6);
		}else if (strncasecmp(LineBuff,"user=",5)==0){
#ifdef DEBUG
			printf("Setting user to \"%s\"\n",LineBuff+5);
#endif							
			snprintf(User, 512, "%s", LineBuff+5);
		}else if (strncasecmp(LineBuff,"password=",9)==0){
#ifdef DEBUG
			printf("Setting password to \"%s\"\n",LineBuff+9);
#endif							
			snprintf(Pass, 512, "%s", LineBuff+9);
		}else if (strncasecmp(LineBuff,"host=",5)==0){
#ifdef DEBUG
			printf("Setting host to \"%s\"\n",LineBuff+5);
#endif							
			snprintf(Host, 512, "%s", LineBuff+5);
		}
	}
	
	return FALSE;
}

/***********************************
* Parse through the snort rules
***********************************/
/*
int ParseSnortSet(FILE* fp){
	char		LineBuff[10240];
	int			RuleNum;
	char		DefaultRule[256];
	int			GID;
	int			Revision;
	
	DEBUGPATH;

	RuleNum=Globals.NumRules;
	snprintf(DefaultRule, MAX_MESSAGE_LEN, "Rule %i\n",RuleNum);
	GID=USER_RULE_START+RuleNum;
	Revision=1;

	while(GetLine(fp, LineBuff, 10240)){
		if (strcasecmp(LineBuff, "</snort>")==0){
#ifdef DEBUG
			printf("All done with this snort section\n");
#endif			
			return TRUE;
		}else{
#ifdef DEBUG		
			printf("Sending \"%s\" to ParseSnort\n", LineBuff);
#endif			
			if (!ParseSnort(LineBuff, RuleNum)){
				printf("Couldn't understand snort rule\n");
				return FALSE;
			}else{
				Globals.NumRules++;
			}
		}
	}
	
	return FALSE;
}
*/

/***********************************
* Make sense out of the rules file
***********************************/
int ParseRules(char* FName){
	FILE*		fp;
	char		LineBuff[10240];
	char*		End;
	char*		Start;
	char		Name[512];
	
	DEBUGPATH;
	
#ifdef DEBUG
	printf("About to parse rule file %s\n", FName);
#endif
	fp=fopen(FName, "r");
	if (!fp){
		snprintf(Name, 512, "rules/%s", FName);
		fp=fopen(Name, "r");
		if (!fp){ 
			printf("Couldn't open rules file %s\n",FName);
			return FALSE;
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
