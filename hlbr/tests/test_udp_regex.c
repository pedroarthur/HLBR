#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "test_udp_regex.h"
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include "../engine/regex.h"

extern GlobalVars	Globals;

typedef struct udp_regexp_data{
	unsigned char	udp_content[MAX_CONTENT_LEN];
	HLBRRegex	*regex;
} UDPRegExpData;

//#define DEBUG
//#define DEBUGMATCH

int UDPDecoderID;


/******************************************
* Apply the Test
******************************************/
int TestUDPRegExp(int PacketSlot, TestNode* Nodes){
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
	printf("Before applying udp regexp tests\n");
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
			UDPRegExpData* data = (UDPRegExpData*)Node->Data;
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
int UDPRegExpAddNode(int TestID, int RuleID, char* Args){
	UDPRegExpData* data;

	DEBUGPATH;

	DBG( PRINT1("Adding a Node with args %s\n",Args) );

	data=calloc(sizeof(UDPRegExpData),1);
	snprintf(data->udp_content, MAX_CONTENT_LEN, "%s", Args);

	data->regex = RegexCompile(data->udp_content, MULTILINE, NOTEMPTY, 0);

	if (!data->regex)
		return FALSE;

	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the UDP RE
*****************************************/
int InitTestUDPRegExp(){
	int TestID;

	DEBUGPATH;

	TestID=CreateTest("UDPRegExp");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "UDP")){
		printf("Failed to Bind to UDP\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "regex");
	Globals.Tests[TestID].AddNode=UDPRegExpAddNode;
	Globals.Tests[TestID].TestFunc=TestUDPRegExp;

	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
