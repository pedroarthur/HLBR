#include "test_tcp_src.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct tcp_src_data{
	NumList*		Ports;
} TCPSrcData;

//#define DEBUG
//#define DEBUGMATCH

int TCPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestTCPSrc(int PacketSlot, TestNode* Nodes){
	unsigned short 		TCPSrc;
	TCPSrcData*			data;
	TCPData*			TData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

	DEBUGPATH;
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the src out of the tcp header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==TCPDecoderID){
			TData=(TCPData*)p->DecoderInfo[i].Data;
			TCPSrc=ntohs(TData->Header->source);
			break;
		}
	}
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the tcp header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp src tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(p,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	Node=Nodes;
	while(Node){
		if (RuleIsActive(PacketSlot, Node->RuleID)){
			data=(TCPSrcData*)Node->Data;
			if (!IsInList(data->Ports, TCPSrc)){
#ifdef DEBUGMATCH
				printf("TCP Src %u doesn't match %u\n", data->tcp_src, TCPSrc);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("TCP Src Matches\n");
			}
		}else{
			printf("Rule is inactive\n");
#endif			
		}
		Node=Node->Next;
	}
	
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
int TCPSrcAddNode(int TestID, int RuleID, char* Args){
	TCPSrcData*			data;

	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );

	data=calloc(sizeof(TCPSrcData),1);

	/*set up the number list*/
	data->Ports=InitNumList(LIST_TYPE_NORMAL);
	if (!AddRangesString(data->Ports, Args, NULL, 0)){
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the TCP Src Field
*****************************************/
int InitTestTCPSrc(){
	int	TestID;

	DEBUGPATH;

	TestID=CreateTest("TCPSrc");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "src");
	Globals.Tests[TestID].AddNode=TCPSrcAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPSrc;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
