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
	NumList*				IPS;
	unsigned char			RuleBits[MAX_RULES/8];
	struct ip_src_data*	Next;
} IPSrcData;

//#define DEBUG
//#define DEBUGMATCH

int IPDecoderID;
IPSrcData* IPSrcHead;

/******************************************
* Apply the Test
******************************************/
int TestIPSrc(int PacketSlot, TestNode* Nodes){
	unsigned long 		IPSrc;
	IPSrcData*			t;
	IPData*				IData;
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
	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
		printf("Failed to get IP header data\n");
		return FALSE;
	}
	
	IPSrc=ntohl(IData->Header->saddr);
	
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
	
	t=IPSrcHead;
	while (t){
		if (!IsInList(t->IPS, IPSrc)){
			/*mark these rules as inactive*/
			NotAndBitFields(p->RuleBits, t->RuleBits, p->RuleBits, Globals.NumRules);
			}
		t=t->Next;
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
	IPSrcData*			t;
	IPSrcData*			last;
#ifdef DEBUG	
	int					i;
#endif

#ifdef DEBUGPATH
	printf("In IPSrcAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(IPSrcData),1);	
	
	/*set up the number list*/
	data->IPS=InitNumList(LIST_TYPE_NORMAL);
	if (!AddIPRanges(data->IPS, Args)){
		free(data);
		data=NULL;
		return FALSE;
	}
	
	/*check to see if this is a duplicate*/
	if (!IPSrcHead){
#ifdef DEBUG
		printf("First IP Source\n");
#endif	
		IPSrcHead=data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
	return TestAddNode(TestID, RuleID, (void*)data);
	}else{
		t=IPSrcHead;
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
* Set up the test of the IP Src Field
*****************************************/
int InitTestIPSrc(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestIPSrc\n");
#endif

	IPSrcHead=NULL;

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
