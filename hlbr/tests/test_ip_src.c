#include "test_ip_src.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ip.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include <netinet/in.h> 
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct ip_src_data{
	NumList*		srcs;
} IPSrcData;

//#define DEBUG
//#define DEBUGMATCH

int IPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestIPSrc(int PacketSlot, TestNode* Nodes){
	unsigned int 		IPSrc;
	IPSrcData*			data;
	IPData*				IData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestIPSrc\n");
#endif

#ifdef DEBUG
	printf("Testing IP Src\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
	/*get the src out of the ip header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==IPDecoderID){
			IData=(IPData*)p->DecoderInfo[i].Data;
			IPSrc=IData->Header->saddr;
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
			data=(IPSrcData*)Node->Data;
			if (!IsInList(data->srcs,ntohl(IPSrc))){
#ifdef DEBUGMATCH
				printf("IP SRc %s",inet_ntoa(*(struct in_addr*)&data->IPSrc));
				printf("does not match %s\n",inet_ntoa(*(struct in_addr*)&IPSrc));
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("IP Src Matches\n");
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
int IPSrcAddNode(int TestID, int RuleID, char* Args){
	IPSrcData*			data;

#ifdef DEBUGPATH
	printf("In IPSrcAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(IPSrcData),1);	
	data->srcs=InitNumList(LIST_TYPE_NORMAL);
	
	if (!AddIPRanges(data->srcs, Args)){
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the IP Src Field
*****************************************/
int InitTestIPSrc(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestIPSrc\n");
#endif

	TestID=CreateTest("IPSrc");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "IP")){
		printf("Failed to Bind to IP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "src");
	Globals.Tests[TestID].AddNode=IPSrcAddNode;
	Globals.Tests[TestID].TestFunc=TestIPSrc;
	
	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
