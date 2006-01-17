#include "test_ethernet_type.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "../decoders/decode_ethernet.h"
#include "../packets/packet.h"
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct ethernet_type_data{
	NumList*		Types;
} EthernetTypeData;

//#define DEBUG
//#define DEBUGMATCH

int EthernetDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestEthernetType(int PacketSlot, TestNode* Nodes){
	unsigned short 		EType;
	EthernetTypeData*	data;
	EthernetData*		EData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestEthernetType\n");
#endif

#ifdef DEBUG
	printf("Testing Ethernet type\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the type out of the ethernet header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==EthernetDecoderID){
			EData=(EthernetData*)p->DecoderInfo[i].Data;
			EType=ntohs(EData->Header->Type);
			break;
		}
	}
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the ethernet header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("\n\n");	
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
			data=(EthernetTypeData*)Node->Data;
			if (!IsInList(data->Types,EType)){
#ifdef DEBUGMATCH
				printf("Ethernet Type %04x does not match test value %04x\n",EType, data->EthernetType);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("Ethernet Type Matches\n");
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
int EthernetTypeAddNode(int TestID, int RuleID, char* Args){
	EthernetTypeData*	data;
	NumAlias			Aliases[2];
	
#ifdef DEBUGPATH
	printf("In EthernetTypeAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding Node with args %s\n",Args);
#endif

	sprintf(Aliases[0].Alias, "IP");
	Aliases[0].Num=ETHERNET_TYPE_IP;
	sprintf(Aliases[1].Alias, "ARP");
	Aliases[1].Num=ETHERNET_TYPE_ARP;


	data=calloc(sizeof(EthernetTypeData),1);
	data->Types=InitNumList(LIST_TYPE_NORMAL);

	if (!AddRangesString(data->Types, Args, Aliases, 2)){
		printf("Couldn't add data\n");
		free(data);
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the Ethernet Type Field
*****************************************/
int InitTestEthernetType(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestInterfaceName\n");
#endif

	TestID=CreateTest("EthernetType");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "Ethernet")){
		printf("Failed to Bind to Ethernet\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "type");
	Globals.Tests[TestID].AddNode=EthernetTypeAddNode;
	Globals.Tests[TestID].TestFunc=TestEthernetType;
	
	EthernetDecoderID=GetDecoderByName("Ethernet");

	return TRUE;
}
