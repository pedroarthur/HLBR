#include "test_tcp_regex.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct tcp_regexp_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
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
	int result;
	int i;

#ifdef DEBUGPATH
	printf("In TestTCPRegExp\n");
#endif

#ifdef DEBUG
	printf("Testing TCP RegExp\n");
#endif	

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
          	regex_t   re;

	  	data=(TCPRegExpData*)Node->Data;
	  	result=0;

	  	result = match(p->RawPacket+p->BeginData, data->tcp_content, &re);
	  	regfree(&re);

		if (result != 0)
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

#ifdef DEBUGPATH
	printf("In TCPRegExpAddNode\n");
#endif

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(TCPRegExpData),1);
	snprintf(data->tcp_content, MAX_CONTENT_LEN, "%s", Args);
	//data = regular expression
	return TestAddNode(TestID, RuleID, (void*)data); //entender o que o TestAddNode faz
}

/****************************************
* Set up the test of the TCP RE
*****************************************/
int InitTestTCPRegExp(){
	int TestID;

#ifdef DEBUGPATH
	printf("In InitTestTCPRegExp\n");
#endif

	TestID=CreateTest("TCPRegExp");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "regexp");
	Globals.Tests[TestID].AddNode=TCPRegExpAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPRegExp;

	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
