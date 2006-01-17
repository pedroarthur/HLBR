#include "test_icmp_code.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_icmp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct icmp_code_data{
	NumList*		codes;
} ICMPCodeData;

//#define DEBUG
//#define DEBUGMATCH

int ICMPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestICMPCode(int PacketSlot, TestNode* Nodes){
	unsigned char 		ICMPCode;
	ICMPCodeData*		data;
	ICMPData*			IData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestICMPCode\n");
#endif

#ifdef DEBUG
	printf("Testing ICMP Code\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the dst out of the ip header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==ICMPDecoderID){
			IData=(ICMPData*)p->DecoderInfo[i].Data;
			ICMPCode=IData->Header->code;
			break;
		}
	}
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the icmp header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying icmp code tests\n");
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
			data=(ICMPCodeData*)Node->Data;
			if (!IsInList(data->codes, ICMPCode)){
#ifdef DEBUGMATCH
				printf("ICMP Code %u doesn't match %u", data->ICMPCode, ICMPCode);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("IP Dst Matches\n");
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
int ICMPCodeAddNode(int TestID, int RuleID, char* Args){
	ICMPCodeData*		data;

#ifdef DEBUGPATH
	printf("In ICMPCodeAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(ICMPCodeData),1);	
	data->codes=InitNumList(LIST_TYPE_NORMAL);
	
	if (!AddRangesString(data->codes, Args, NULL, 0)){
		printf("Couldn't add data\n");
		free(data);
		return FALSE;
	}

	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the ICMP Code Field
*****************************************/
int InitTestICMPCode(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestICMPCode\n");
#endif

	TestID=CreateTest("ICMPCode");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "ICMP")){
		printf("Failed to Bind to ICMP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "code");
	Globals.Tests[TestID].AddNode=ICMPCodeAddNode;
	Globals.Tests[TestID].TestFunc=TestICMPCode;
	
	ICMPDecoderID=GetDecoderByName("ICMP");

	return TRUE;
}
