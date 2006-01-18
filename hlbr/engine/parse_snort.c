#include "parse_snort.h"
#include "../actions/action.h"
#include "message.h"
#include "parse_rules.h"
#include <string.h>
#include <stdlib.h>

#define DEBUG

extern GlobalVars Globals;

/********************************************************
* compatibility for snort signatures
* this will work as well as I have time to update it
********************************************************/
int ParseSnort(char* DecoderLine, int RuleNum){
	char*	c;
	char*	c2;
	char*	action;
	char*	proto;
	char*	ip1;
	char*	port1;
	char*	direction;
	char*	ip2;
	char*	port2;
	unsigned char	Buff[10240];
	
#ifdef DEBUG
	printf("Parsing snort rule \"%s\"\n",DecoderLine);
	printf("-----------------------------\n");
#endif
	
	/*****************/
	/*find the action*/
	/*****************/
	c=DecoderLine;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected action\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("Action should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	action=c;
#ifdef DEBUG
	printf("Action is %s\n",action);
#endif	

	/************************/
	/*parse the header stuff*/
	/************************/
	c=c2+1;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected protocol\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("Protocol should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	proto=c;
#ifdef DEBUG
	printf("proto is %s\n",proto);
#endif	

	c=c2+1;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected IP1\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("IP1 should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	ip1=c;
#ifdef DEBUG
	printf("ip1 is %s\n",ip1);
#endif	

	c=c2+1;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected Port1\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("Port1 should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	port1=c;
#ifdef DEBUG
	printf("port1 is %s\n",port1);
#endif	

	c=c2+1;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected Direction\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("Direction should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	direction=c;
#ifdef DEBUG
	printf("Direction is %s\n",direction);
#endif	

	c=c2+1;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected IP2\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("IP2 should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	ip2=c;
#ifdef DEBUG
	printf("ip2 is %s\n",ip2);
#endif	

	c=c2+1;
	while ((*c==' ') && (*c!=0x00)) c++;
	if (!*c){printf("Expected Port2\n");return FALSE;}
	
	c2=c+1;
	while ( (*c2!=' ') && (*c2!=0x00)) c2++;
	if (!*c2){printf("Port2 should be terminated with a space\n");return FALSE;}
	
	*c2=0x00;
	port2=c;
#ifdef DEBUG
	printf("port2 is %s\n",port2);
	printf("-----------------------------\n");
#endif	

	/**********************************/
	/* Make hlbr lines out of these*/
	/**********************************/
	if ( (Globals.Rules[RuleNum].Action=SetAction(RuleNum, action))==ACTION_NONE){
		printf("Error: Couldn't find action %s\n",action);
		return FALSE;
	}	
	
	if (strcasecmp(ip1, "any")!=0){
		if (*ip1=='$') ip1++;
		snprintf(Buff, 10240, "ip src(%s)",ip1);
		if (!ParseDecoderLine(Buff, RuleNum)){
			printf("Error parsing ip1\n");
			return FALSE;
		}
	}

	if (strcasecmp(ip2, "any")!=0){
		if (*ip2=='$') ip2++;
		snprintf(Buff, 10240, "ip dst(%s)",ip1);
		if (!ParseDecoderLine(Buff, RuleNum)){
			printf("Error parsing ip2\n");
			return FALSE;
		}
	}

	if (strcasecmp(port1, "any")!=0){
		snprintf(Buff, 10240, "%s src(%s)",proto, port1);
		if (!ParseDecoderLine(Buff, RuleNum)){
			printf("Error parsing port1\n");
			return FALSE;
		}
	}

	if (strcasecmp(port2, "any")!=0){
		snprintf(Buff, 10240, "%s dst(%s)",proto, port2);
		if (!ParseDecoderLine(Buff, RuleNum)){
			printf("Error parsing port2\n");
			return FALSE;
		}
	}

	if (strcasecmp(direction, "->")!=0){
		printf("We can only parse -> rules right now\n");
		return FALSE;
	}

	/***********************/
	/*now parse the options*/
	/***********************/
	c=c2+1;
	while ((*c=='(') && (*c!=0x00)) c++;
	if (!*c){printf("Expected \"(\"\n");return FALSE;}
	
	while (1){	
		while ((*c==' ') && (*c!=0x00)) c++;
		if (!*c){printf("Expected rule option\n");return FALSE;}
		
		if (*c==')') break;
		
		c2=c;
		while ( (*c2!=';') && (*c2!=0x00)) c2++;
		if (!*c){printf("Expected \";\" option\n");return FALSE;}
		
		*c2=0x00;

		if (strncasecmp("msg:", c, 4)==0){
#ifdef DEBUG
			printf("Setting message to %s\n",c+4);
#endif
			Globals.Rules[RuleNum].MessageFormat=ParseMessageString(c+4);
		}else if (strncasecmp("sid:", c, 4)==0){
			Globals.Rules[RuleNum].GlobalID=atoi(c+4);
		}else if (strncasecmp("rev:", c, 4)==0){
			Globals.Rules[RuleNum].Revision=atoi(c+4);
		}else if (strncasecmp("content:", c, 8)==0){
			snprintf(Buff, 10240, "%s content(%s)",proto, c+8);
			if (!ParseDecoderLine(Buff, RuleNum)){
				printf("Error parsing option %s\n", c);
				return FALSE;
			}
		}else{
			printf("Unknown option %s\n",c);
		}

		
		c=c2+1;
	}
	
	return TRUE;
}
