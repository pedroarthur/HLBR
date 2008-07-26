//#define DEBUG
//#define DEBUGMATCH

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "test_tcp_regex.h"
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/regex.h"

extern GlobalVars	Globals;

typedef struct tcp_regexp_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
	HLBRRegex	*regex;
} TCPRegExpData;

int TCPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestTCPRegExp(int PacketSlot, TestNode* Nodes){
	PacketRec* p;
	TestNode* Node;

#ifdef DEBUGMATCH
	int i;
#endif

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	if (!Nodes)
		return FALSE;

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
			TCPRegExpData* data = (TCPRegExpData*)Node->Data;
#ifdef DEBUGMATCH
			if (!RegexExecDebug(data->regex, p->RawPacket + p->BeginData, p->PacketLen - p->BeginData))
#else
			if (!RegexExec(data->regex, p->RawPacket + p->BeginData, p->PacketLen - p->BeginData))
#endif
				SetRuleInactive(PacketSlot, Node->RuleID);
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

	DEBUGPATH;

	DBG( PRINT1("Adding a Node with args %s\n",Args) );

	data=calloc(sizeof(TCPRegExpData),1);
	snprintf(data->tcp_content, MAX_CONTENT_LEN, "%s", Args);

	data->regex = RegexCompile(data->tcp_content, PCRE_MULTILINE, NOTEMPTY, 0);

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

#ifdef DEBUG
#undef DEBUG
#endif
#ifdef DEBUGMATCH
#undef DEBUGMATCH
#endif
