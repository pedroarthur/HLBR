#include "test_ip_ttl.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ip.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"
#include "../engine/bits.h"

extern GlobalVars	Globals;

typedef struct ip_ttl_data{
	NumList*				TTLs;
	unsigned char			RuleBits[MAX_RULES/8];
	struct ip_ttl_data*	Next;
} IPTTLData;

//#define DEBUG
//#define DEBUGMATCH

int IPDecoderID;
IPTTLData*	IPTTLHead;

/******************************************
* Apply the Test with collapsed rules
******************************************/
int TestIPTTL(int PacketSlot, TestNode* Nodes){
	unsigned char 		IPTTL;
	IPTTLData*			t;
	IPData*				IData;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestIPTTL\n");
#endif

#ifdef DEBUG
	printf("Testing IP TTL\n");
#endif	
	
	if (!Nodes) return FALSE;
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the ttl out of the ip header*/
	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
		printf("Failed to get IP header data\n");
		return FALSE;
	}

	IPTTL=IData->Header->ttl;
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the ip header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying ip ttl tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	t=IPTTLHead;
	while (t){
		if (!IsInList(t->TTLs, IPTTL)){
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
int IPTTLAddNode(int TestID, int RuleID, char* Args){
	IPTTLData*			data;
	IPTTLData*			t;
	IPTTLData*			last;
#ifdef DEBUG	
	int					i;
#endif

#ifdef DEBUGPATH
	printf("In IPTTLAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(IPTTLData),1);
	
	/*set up the number list*/
	data->TTLs=InitNumList(LIST_TYPE_NORMAL);
	if (!AddIPRanges(data->TTLs, Args)){
		free(data);
		data=NULL;
		return FALSE;
	}
	
	/*check to see if this is a duplicate*/
	if (!IPTTLHead){
#ifdef DEBUG
		printf("First IP Dest\n");
#endif	
		IPTTLHead=data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);
	}else{
		t=IPTTLHead;
		last=t;
		while (t){
			if (NumListCompare(data->TTLs, t->TTLs)){
#ifdef DEBUG
				printf("This is a duplicate\n");
#endif			
				DestroyNumList(data->TTLs);
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
* Set up the test of the IP TTL Field
*****************************************/
int InitTestIPTTL(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestIPTTL\n");
#endif

	IPTTLHead=NULL;

	TestID=CreateTest("IPTTL");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "IP")){
		printf("Failed to Bind to IP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "ttl");
	Globals.Tests[TestID].AddNode=IPTTLAddNode;
	Globals.Tests[TestID].TestFunc=TestIPTTL;
	
	IPDecoderID=GetDecoderByName("IP");

	return TRUE;
}
