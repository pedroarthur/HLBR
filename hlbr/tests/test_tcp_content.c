#include "test_tcp_content.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct tcp_content_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
} TCPContentData;

//#define DEBUG
//#define DEBUGMATCH

int 			TCPDecoderID;
JTree			TCPContentTree;

#ifdef OLD_MATCH
/********************************************
* Returns TRUE is Candidate is in Packet
********************************************/
int MatchString(char* Candidate, int CLen, char* Packet, int PLen){
	int 	i;
	int		j;

	DEBUGPATH;

	if (CLen<PLen) return FALSE;
	
	for (i=0;i<PLen-CLen+1;i++){
		if (Packet[i]==Candidate[0]){
			for (j=1;j<CLen-1;j++){
				if (Packet[j+i]!=Candidate[j]) break;
			}
			if (j==(CLen-1)) return TRUE;
		}
	}

	return FALSE;
}
#endif

/******************************************
* Apply the Test
******************************************/
int TestTCPContent(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
#ifdef DEBUGMATCH	
	int					i;
#endif	

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp content tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	

	MatchStrings(&TCPContentTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
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
int TCPContentAddNode(int TestID, int RuleID, char* Args){
	TCPContentData*		data;

	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );

	data=calloc(sizeof(TCPContentData),1);
	snprintf(data->tcp_content, MAX_CONTENT_LEN, Args);

	if (!AddStringJTree(&TCPContentTree, Args, strlen(Args), RuleID)){
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
int TestTCPContentFinishedSetup(){
  DEBUGPATH;

	return FinalizeJTree(&TCPContentTree);
}

/****************************************
* Set up the test of the TCP Content
*****************************************/
int InitTestTCPContent(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestTCPContent\n");
#endif

	InitJTree(&TCPContentTree, FALSE);

	TestID=CreateTest("TCPContent");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "content");
	Globals.Tests[TestID].AddNode=TCPContentAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPContent;
	Globals.Tests[TestID].FinishedSetup=TestTCPContentFinishedSetup;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
