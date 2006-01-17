#include "test_tcp_stream_content.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp_stream.h"
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/bmtree.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct tcp_stream_content_data{
	unsigned char	tcp_stream_content[MAX_CONTENT_LEN];
} TCPStreamContentData;

#define DEBUG
//#define DEBUGMATCH

int 			TCPStreamDecoderID;
BMTree			TCPStreamContentTree;

/******************************************
* Apply the Test
******************************************/
int TestTCPStreamContent(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
#ifdef DEBUGMATCH	
	int					i;
#endif	

#ifdef DEBUGPATH
	printf("In TestTCPStreamContent\n");
#endif

#ifdef DEBUG
	printf("Testing TCPStream Content\n");
#endif	
	
	if (!Nodes) return FALSE;
	
	p=&Globals.Packets[PacketSlot];
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp stream content tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(p,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	

	MatchStringTree(&TCPStreamContentTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(p,i))
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
int TCPStreamContentAddNode(int TestID, int RuleID, char* Args){
	TCPStreamContentData*		data;

#ifdef DEBUGPATH
	printf("In TCPStreamContentAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(TCPStreamContentData),1);
	snprintf(data->tcp_stream_content, MAX_CONTENT_LEN, Args);

	if (!AddToTree(&TCPStreamContentTree, Args, strlen(Args), RuleID)){
		printf("Failed to add to tree\n");
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the TCP Stream Content
*****************************************/
int InitTestTCPStreamContent(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestTCPStreamContent\n");
#endif

	InitTree(&TCPStreamContentTree, FALSE);

	TestID=CreateTest("TCPStreamContent");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCPStream")){
		printf("Failed to Bind to TCPStream\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "content");
	Globals.Tests[TestID].AddNode=TCPStreamContentAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPStreamContent;
	
	TCPStreamDecoderID=GetDecoderByName("TCPStream");

	return TRUE;
}
