#include "test_ip_dst.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ip.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"
#include "../engine/bits.h"

extern GlobalVars	Globals;

typedef struct ip_dst_data{
	NumList*				IPS;
	unsigned char			RuleBits[MAX_RULES/8];
	struct ip_dst_data*	Next;
} IPDstData;

//#define DEBUG
//#define DEBUGMATCH

int IPDecoderID;
IPDstData*	IPDstHead;

/******************************************
* Apply the Test with collapsed rules
******************************************/
int TestIPDst(int PacketSlot, TestNode* Nodes){
	unsigned long 		IPDst;
	IPDstData*			t;
	IPData*				IData;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestIPDst\n");
#endif

#ifdef DEBUG
	printf("Testing IP Dst\n");
#endif	
	
	if (!Nodes) return FALSE;
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the dst out of the ip header*/
	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
		printf("Failed to get IP header data\n");
		return FALSE;
	}

	IPDst=ntohl(IData->Header->daddr);
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the ip header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUG
	printf("%s->",inet_ntoa(*(struct in_addr*)&IData->Header->saddr));
	printf("%s\n",inet_ntoa(*(struct in_addr*)&IData->Header->daddr));
	printf("As int %u\n",IData->Header->daddr);
	printf("Host order %u\n",ntohl(IData->Header->daddr));
#endif

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying ip dst tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	t=IPDstHead;
	while (t){
		if (!IsInList(t->IPS, IPDst)){
			/*mark these rules as inactive*/
			NotAndBitFields(p->RuleBits, t->RuleBits, p->RuleBits, Globals.NumRules);
		}
		t=t->Next;
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
* Add a rule node to this test
******************************************/
int IPDstAddNode(int TestID, int RuleID, char* Args){
	IPDstData*			data;
	IPDstData*			t;
	IPDstData*			last;
#ifdef DEBUG	
	int					i;
#endif

#ifdef DEBUGPATH
	printf("In IPDstAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(IPDstData),1);
	
	/*set up the number list*/
	data->IPS=InitNumList(LIST_TYPE_NORMAL);
	if (!AddIPRanges(data->IPS, Args)){
		free(data);
		data=NULL;
		return FALSE;
	}
	
	/*check to see if this is a duplicate*/
	if (!IPDstHead){
#ifdef DEBUG
		printf("First IP Dest\n");
#endif	
		IPDstHead=data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);
	}else{
		t=IPDstHead;
		last=t;
		while (t){
			if (NumListCompare(data->IPS, t->IPS)){
#ifdef DEBUG
				printf("This is a duplicate\n");
#endif			
				DestroyNumList(data->IPS);
				free(data);
				data=NULL;
				SetBit(t->RuleBits, Globals.NumRules, RuleID, 1);
#ifdef DEBUG1
				for (i=0;i<Globals.NumRules+1;i++)
				if (GetBit(t->RuleBits, Globals.NumRules, i))
				printf("Bit %i is set\n",i);
#endif				
				return TestAddNode(TestID, RuleID, (void*)t);		
			}
			
			last=t;
			t=t->Next;
		}
		
#ifdef DEBUG
		printf("This is a new one\n");
#endif		
		last->Next=data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);		
	}
}

/****************************************
* Set up the test of the IP Dst Field
*****************************************/
int InitTestIPDst(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestIPDst\n");
#endif

	IPDstHead=NULL;

	TestID=CreateTest("IPDst");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "IP")){
		printf("Failed to Bind to IP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "dst");
	Globals.Tests[TestID].AddNode=IPDstAddNode;
	Globals.Tests[TestID].TestFunc=TestIPDst;
	
	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
