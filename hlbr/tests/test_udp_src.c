#include "test_udp_src.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"
#include "../engine/bits.h"

extern GlobalVars	Globals;

typedef struct udp_src_data{
	NumList*				Ports;
	unsigned char			RuleBits[MAX_RULES/8];
	struct udp_src_data*	Next;
} UDPSrcData;

//#define DEBUG
//#define DEBUGMATCH

int UDPDecoderID;
UDPSrcData*	UDPSrcHead;


/******************************************
* Apply the Test with collapsed rules
******************************************/
int TestUDPSrc(int PacketSlot, TestNode* Nodes){
	unsigned short 		UDPSrc;
	UDPSrcData*			t;
	UDPData*			TData;
	int					i;
	PacketRec*			p;

	DEBUGPATH;
	
	if (!Nodes) return FALSE;
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the src out of the udp header*/
	if (!GetDataByID(PacketSlot, UDPDecoderID, (void**)&TData)){
		printf("Failed to get UDP header data\n");
		return FALSE;
	}

	UDPSrc=ntohs(TData->Header->dest);
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the udp header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying udp src tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	t=UDPSrcHead;
	while (t){
		if (!IsInList(t->Ports, UDPSrc)){
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
int UDPSrcAddNode(int TestID, int RuleID, char* Args){
	UDPSrcData*			data;
	UDPSrcData*			t;
	UDPSrcData*			last;

	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );

	data=calloc(sizeof(UDPSrcData),1);
	
	/*set up the number list*/
	data->Ports=InitNumList(LIST_TYPE_NORMAL);
	if (!AddRangesString(data->Ports, Args, NULL, 0)){
		free(data);
		data=NULL;
		return FALSE;
	}
	
	/*check to see if this is a duplicate*/
	if (!UDPSrcHead){
#ifdef DEBUG
		printf("First UDP Dest\n");
#endif	
		UDPSrcHead=data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);
	}else{
		t=UDPSrcHead;
		last=t;
		while (t){
			if (NumListCompare(data->Ports, t->Ports)){
#ifdef DEBUG
				printf("This is a duplicate\n");
#endif			
				DestroyNumList(data->Ports);
				free(data);
				data=NULL;
				SetBit(t->RuleBits, Globals.NumRules, RuleID, 1);
#ifdef DEBUG
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
* Set up the test of the UDP Src Field
*****************************************/
int InitTestUDPSrc(){
	int	TestID;

	DEBUGPATH;

	UDPSrcHead=NULL;

	TestID=CreateTest("UDPSrc");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "UDP")){
		printf("Failed to Bind to UDP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "src");
	Globals.Tests[TestID].AddNode=UDPSrcAddNode;
	Globals.Tests[TestID].TestFunc=TestUDPSrc;
	
	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
