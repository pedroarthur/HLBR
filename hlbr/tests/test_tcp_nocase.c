#include "test_tcp_nocase.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct tcp_nocase_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
} TCPNoCaseData;

//#define DEBUG
//#define DEBUGMATCH

int 			TCPDecoderID;
JTree			TCPNoCaseTree;

/******************************************
* Apply the Test
******************************************/
int TestTCPNoCase(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
	TCPNoCaseData* data;
#ifdef DEBUGMATCH	
	int					i;
#endif	

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp no case tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	MatchStrings(&TCPNoCaseTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
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
* Add a rule node to this test
******************************************/
int TCPNoCaseAddNode(int TestID, int RuleID, char* Args){
	TCPNoCaseData*		data;

	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );

	data=calloc(sizeof(TCPNoCaseData),1);
	snprintf(data->tcp_content, MAX_CONTENT_LEN, "%s", Args);

	if (!AddStringJTree(&TCPNoCaseTree, Args, strlen(Args), RuleID)){
		printf("Failed to add to tree\n");
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Called when we're all done adding rules
****************************************/
int TestTCPNoCaseFinishedSetup(){
  DEBUGPATH;

	return FinalizeJTree(&TCPNoCaseTree);
}

/****************************************
* Set up the test of the TCP NoCase
*****************************************/
int InitTestTCPNoCase(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&TCPNoCaseTree, TRUE);

	TestID=CreateTest("TCPNoCase");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "nocase");
	Globals.Tests[TestID].AddNode=TCPNoCaseAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPNoCase;
	Globals.Tests[TestID].FinishedSetup=TestTCPNoCaseFinishedSetup;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
