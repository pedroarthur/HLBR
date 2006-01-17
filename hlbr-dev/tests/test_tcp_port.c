#include "test_tcp_port.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct tcp_port_data{
	NumList*		Ports;
} TCPPortData;

//#define DEBUG
//#define DEBUGMATCH

int TCPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestTCPPort(int PacketSlot, TestNode* Nodes){
	unsigned short 		TCPSrc;
	unsigned short 		TCPDst;
	TCPPortData*		data;
	TCPData*			TData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestTCPPort\n");
#endif

#ifdef DEBUG
	printf("Testing TCP Port\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the port out of the tcp header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==TCPDecoderID){
			TData=(TCPData*)p->DecoderInfo[i].Data;
			TCPSrc=ntohs(TData->Header->source);
			TCPDst=ntohs(TData->Header->dest);
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
	printf("Before applying tcp port tests\n");
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
			data=(TCPPortData*)Node->Data;
			if ( (!IsInList(data->Ports, TCPSrc)) && (!IsInList(data->Ports, TCPDst)) ){
#ifdef DEBUGMATCH
				printf("TCP Port %u doesn't match %u\n", data->tcp_port, TCPPort);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("TCP Port Matches\n");
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
int TCPPortAddNode(int TestID, int RuleID, char* Args){
	TCPPortData*			data;

#ifdef DEBUGPATH
	printf("In TCPPortAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(TCPPortData),1);

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
* Set up the test of the TCP Port Field
*****************************************/
int InitTestTCPPort(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestTCPPort\n");
#endif

	TestID=CreateTest("TCPPort");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "port");
	Globals.Tests[TestID].AddNode=TCPPortAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPPort;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
