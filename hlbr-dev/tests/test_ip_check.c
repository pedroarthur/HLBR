#include "test_ip_check.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ip.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"


extern GlobalVars	Globals;

typedef struct ip_check_data{
	NumList*	Checks;
} IPCheckData;

//#define DEBUG
//#define DEBUGMATCH

int IPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestIPCheck(int PacketSlot, TestNode* Nodes){
	unsigned short 		IPCheck;
	IPCheckData*		data;
	IPData*				IData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestIPCheck\n");
#endif

#ifdef DEBUG
	printf("Testing IP Check\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the check out of the ip header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==IPDecoderID){
			IData=(IPData*)p->DecoderInfo[i].Data;
			IPCheck=IData->Header->check;
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
			data=(IPCheckData*)Node->Data;
			if (!IsInList(data->Checks, IPCheck)){
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("IP Chck Matches\n");
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
int IPCheckAddNode(int TestID, int RuleID, char* Args){
	IPCheckData*		data;

#ifdef DEBUGPATH
	printf("In IPCheckAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif
	

	data=calloc(sizeof(IPCheckData),1);	
	
	data->Checks=InitNumList(LIST_TYPE_NORMAL);
	
	if (!AddRangesString(data->Checks, Args, NULL, 0)){
		printf("Couldn't add data\n");
		free(data);
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the IP chek Field
*****************************************/
int InitTestIPCheck(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestIPCheck\n");
#endif

	TestID=CreateTest("IPCheck");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "IP")){
		printf("Failed to Bind to IP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "check");
	Globals.Tests[TestID].AddNode=IPCheckAddNode;
	Globals.Tests[TestID].TestFunc=TestIPCheck;
	
	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
