#include "test_ip_proto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ip.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

#define IP_PROTO_ICMP	1
#define IP_PROTO_IGMP	2
#define IP_PROTO_TCP	6
#define IP_PROTO_UDP	17
#define IP_PROTO_PIM	0x67
#define IP_PROTO_OSPF	0x59

extern GlobalVars	Globals;

typedef struct ip_proto_data{
	NumList*	Protos;
} IPProtoData;

//#define DEBUG
//#define DEBUGMATCH

int IPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestIPProto(int PacketSlot, TestNode* Nodes){
	unsigned char 		IPProto;
	IPProtoData*		data;
	IPData*				IData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

	DEBUGPATH;
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the proto out of the ip header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==IPDecoderID){
			IData=(IPData*)p->DecoderInfo[i].Data;
			IPProto=IData->Header->protocol;
			break;
		}
	}
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the ip header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying interface name tests\n");
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
			data=(IPProtoData*)Node->Data;
			if (!IsInList(data->Protos, IPProto)){
#ifdef DEBUGMATCH
				printf("IP Proto %u ",data->IPProto);
				printf("does not match %u\n",IPProto);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("IP Proto Matches\n");
			}
		}else{
			printf("Rule is inactive\n");
#endif			
		}
		Node=Node->Next;
	}
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("After applying interface name tests\n");
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
int IPProtoAddNode(int TestID, int RuleID, char* Args){
	IPProtoData*		data;
	NumAlias			Aliases[6];

	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );
	
	snprintf(Aliases[0].Alias,512,"TCP");
	Aliases[0].Num=IP_PROTO_TCP;
	snprintf(Aliases[1].Alias,512,"UDP");
	Aliases[1].Num=IP_PROTO_UDP;
	snprintf(Aliases[2].Alias,512,"ICMP");
	Aliases[2].Num=IP_PROTO_ICMP;
	snprintf(Aliases[3].Alias,512,"IGMP");
	Aliases[3].Num=IP_PROTO_IGMP;
	snprintf(Aliases[4].Alias,512,"PIM");
	Aliases[4].Num=IP_PROTO_PIM;
	snprintf(Aliases[5].Alias,512,"OSPF");
	Aliases[5].Num=IP_PROTO_OSPF;

	data=calloc(sizeof(IPProtoData),1);	
	
	data->Protos=InitNumList(LIST_TYPE_NORMAL);
	
	if (!AddRangesString(data->Protos, Args, Aliases, 6)){
		printf("Couldn't add data\n");
		free(data);
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the IP Proto Field
*****************************************/
int InitTestIPProto(){
	int	TestID;

	DEBUGPATH;

	TestID=CreateTest("IPProto");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "IP")){
		printf("Failed to Bind to IP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "proto");
	Globals.Tests[TestID].AddNode=IPProtoAddNode;
	Globals.Tests[TestID].TestFunc=TestIPProto;
	
	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
