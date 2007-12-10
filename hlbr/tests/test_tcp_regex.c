#include "test_tcp_regex.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include <pcre.h>


extern GlobalVars	Globals;

typedef struct tcp_regexp_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
	pcre		*re;
	pcre_extra	*ere;
} TCPRegExpData;

//#define DEBUG
//#define DEBUGMATCH

int TCPDecoderID;


/******************************************
* Apply the Test
******************************************/
int TestTCPRegExp(int PacketSlot, TestNode* Nodes){
	PacketRec* p;
	TestNode* Node;
	TCPRegExpData* data;
	/* int result; */
	int i;

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp regexp tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif
	Node=Nodes;

	while (Node) {

		if (RuleIsActive(PacketSlot, Node->RuleID)) {
			pcre *re;

			/* I thought it was unnecessary to declare 'int result' cause
			 * it was not used for nothing unless to execute the 'if'
			 * conditional, so it was just a waste of time. If you think it
			 * is a necessary 'evil' please undo my changes.
			 *
			 * If DEBUGMATCH macro is set, the 'char regex_str[50]' variable
			 * will return some match information.
			 * */

#ifdef DEBUGMATCH
			char regex_str[50];
#endif
			data=(TCPRegExpData*)Node->Data;

#ifdef DEBUGMATCH
			if (pcre_exec(data->re, data->ere, p->RawPacket + P->BeginData, p->PacketLen - p->BeginData, 0, PCRE_NOTEMPTY, regex_str, 50) < 0) {
				printf ("%s\n", regex_str);
#else
			if (pcre_exec(data->re, data->ere, p->RawPacket + p->BeginData, p->PacketLen - p->BeginData, 0, PCRE_NOTEMPTY, NULL, 0) < 0)
#endif
				SetRuleInactive(PacketSlot, Node->RuleID);
#ifdef DEBUGMATCH
			}
#endif
		}

                Node=Node->Next;
	}


#ifdef DEBUGMATCH
	printf("**************************************\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif

	return TRUE;
}

/******************************************
* Add a rule node to this tets
******************************************/
int TCPRegExpAddNode(int TestID, int RuleID, char* Args){
	TCPRegExpData* data;
	int erofset;
	int errocode;
	const char *errors;

	DEBUGPATH;

	DBG( PRINT1("Adding a Node with args %s\n",Args) );

	data=calloc(sizeof(TCPRegExpData),1);
	snprintf(data->tcp_content, MAX_CONTENT_LEN, "%s", Args);

	data->re = pcre_compile2(data->tcp_content, PCRE_MULTILINE, &errocode, &errors, &erofset, NULL);

	if (errocode) {
		printf ("Regular Expression Parse Error: TestID=%d RuleID=%d Args=%s Errocode=%d Error=\"%s\" Erroroffset=%d\n"\
				, TestID, RuleID, Args, errocode, errors, erofset);
		return 1;
	}

	data->ere = pcre_study(data->re, 0, &errors);
	if (errors != NULL) {
		printf ("Regular Expression Parse Error: TestID=%d RuleID=%d Args=%s Error=\"%s\"\n"\
				, TestID, RuleID, Args, errors);
		return 1;
	}

	//data = regular expression
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the TCP RE
*****************************************/
int InitTestTCPRegExp(){
	int TestID;

	DEBUGPATH;

	TestID=CreateTest("TCPRegExp");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "regex");
	Globals.Tests[TestID].AddNode=TCPRegExpAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPRegExp;

	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
