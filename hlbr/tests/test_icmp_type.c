#include "test_icmp_type.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_icmp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct icmp_type_data{
	NumList*	types;
} ICMPTypeData;

//#define DEBUG
//#define DEBUGMATCH

int ICMPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestICMPType(int PacketSlot, TestNode* Nodes){
	unsigned char 		ICMPType;
	ICMPTypeData*		data;
	ICMPData*			IData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestICMPType\n");
#endif

#ifdef DEBUG
	printf("Testing ICMP Type\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the dst out of the ip header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==ICMPDecoderID){
			IData=(ICMPData*)p->DecoderInfo[i].Data;
			ICMPType=IData->Header->type;
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
	printf("Before applying icmp type tests\n");
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
			data=(ICMPTypeData*)Node->Data;
			if (!IsInList(data->types, ICMPType)){
#ifdef DEBUGMATCH
				printf("ICMP Type %u doesn't match %u\n", data->icmp_type, ICMPType);
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
int ICMPTypeAddNode(int TestID, int RuleID, char* Args){
	ICMPTypeData*		data;
	NumAlias			Aliases[2];

#ifdef DEBUGPATH
	printf("In ICMPTypeAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	sprintf(Aliases[0].Alias, "Echo");
	Aliases[0].Num=ICMP_TYPE_ECHO;
	sprintf(Aliases[1].Alias, "EchoReply");
	Aliases[1].Num=ICMP_TYPE_ECHOREPLY;

	data=calloc(sizeof(ICMPTypeData),1);		
	data->types=InitNumList(LIST_TYPE_NORMAL);
	
	if (!AddRangesString(data->types, Args, Aliases, 2)){
		printf("Couldn't add data\n");
		free(data);
		return FALSE;
	}

	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the ICMP Type Field
*****************************************/
int InitTestICMPType(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestICMPType\n");
#endif

	TestID=CreateTest("ICMPType");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "ICMP")){
		printf("Failed to Bind to ICMP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "type");
	Globals.Tests[TestID].AddNode=ICMPTypeAddNode;
	Globals.Tests[TestID].TestFunc=TestICMPType;
	
	ICMPDecoderID=GetDecoderByName("ICMP");

	return TRUE;
}
