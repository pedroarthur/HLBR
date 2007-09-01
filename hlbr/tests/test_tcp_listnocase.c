#include "test_tcp_listnocase.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"
#include "../engine/parse_config.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct tcp_nocase_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
} TCPListNoCaseData;

//#define DEBUG
//#define DEBUGMATCH

int 			TCPDecoderID;
JTree			TCPListNoCaseTree;

/******************************************
* Apply the Test
******************************************/
int TestTCPListNoCase(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
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

	MatchStrings(&TCPListNoCaseTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
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
* Args is the file name of the word list
******************************************/
int TCPListNoCaseAddNode(int TestID, int RuleID, char* Args){
	TCPListNoCaseData*	data;
	FILE*			listf;
	char			LineBuff[10240];

	DEBUGPATH;

	listf = fopen(Args, "r");
	if (!listf){
		printf("Couldn't open file %s for 'tcp listnocase' test\n", Args);
		return FALSE;
	}

#ifdef DEBUG
	printf("Adding a Node with args from file %s\n", Args);
#endif

//			data=calloc(sizeof(TCPListNoCaseData),1);
//			snprintf(data->tcp_content, MAX_CONTENT_LEN, "%s", Args);
	data=NULL;

	while (GetLine(listf, LineBuff, 10240)) {
#ifdef DEBUG
			printf("Adding: %s\n", LineBuff);
#endif

			if (!AddStringJTree(&TCPListNoCaseTree, LineBuff, strlen(LineBuff), RuleID)) {
					printf("Failed to add to tree\n");
//					free(data);
//					data=NULL;
					return FALSE;
			}
	}

	fclose(listf);
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Called when we're all done adding rules
****************************************/
int TestTCPListNoCaseFinishedSetup(){
  DEBUGPATH;

	return FinalizeJTree(&TCPListNoCaseTree);
}


/****************************************
* Set up the test of the TCP NoCase
*****************************************/
int InitTestTCPListNoCase(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&TCPListNoCaseTree, TRUE);

	TestID=CreateTest("TCPListNoCase");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "listnocase");
	Globals.Tests[TestID].AddNode=TCPListNoCaseAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPListNoCase;
	Globals.Tests[TestID].FinishedSetup=TestTCPListNoCaseFinishedSetup;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
