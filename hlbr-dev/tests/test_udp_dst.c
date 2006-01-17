#include "test_udp_dst.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct udp_dst_data{
	NumList*		Ports;
} UDPDstData;

//#define DEBUG
//#define DEBUGMATCH

int UDPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestUDPDst(int PacketSlot, TestNode* Nodes){
	unsigned short 		UDPDst;
	UDPDstData*			data;
	UDPData*			TData;
	TestNode*			Node;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestUDPDst\n");
#endif

#ifdef DEBUG
	printf("Testing UDP Dst\n");
#endif	
	
	if (!Nodes) return FALSE;
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the dst out of the udp header*/
	/*todo: make this more efficient*/
	if (!GetDataByID(PacketSlot, UDPDecoderID, (void**)&TData)){
#ifdef DEBUG
		printf("This isn't a udp packet\n");
#endif	
		return FALSE;
	}
	
	UDPDst=ntohs(TData->Header->dest);
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying udp dst tests\n");
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
			data=(UDPDstData*)Node->Data;
			if (!IsInList(data->Ports, UDPDst)){
#ifdef DEBUGMATCH
				printf("UDP Dst %u doesn't match\n", UDPDst);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("UDP Dst Matches\n");
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
int UDPDstAddNode(int TestID, int RuleID, char* Args){
	UDPDstData*			data;

#ifdef DEBUGPATH
	printf("In UDPDstAddNode\n");
#endif

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(UDPDstData),1);	
	
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
* Set up the test of the UDP Dst Field
*****************************************/
int InitTestUDPDst(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestUDPDst\n");
#endif

	TestID=CreateTest("UDPDst");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "UDP")){
		printf("Failed to Bind to UDP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "dst");
	Globals.Tests[TestID].AddNode=UDPDstAddNode;
	Globals.Tests[TestID].TestFunc=TestUDPDst;
	
	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
