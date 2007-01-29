#include "test_tcp_dst.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"
#include "../engine/bits.h"

extern GlobalVars	Globals;

typedef struct tcp_dst_data {
	NumList*		Ports;
	unsigned char		RuleBits[MAX_RULES/8];
	struct tcp_dst_data*	Next;
} TCPDstData;

//#define DEBUG
//#define DEBUGMATCH

int		TCPDecoderID;
TCPDstData*	TCPDstHead;

/**
 * Apply the TCPDst test (old version).
 */
int TestTCPDstOld(int PacketSlot, TestNode* Nodes)
{
	unsigned short 	TCPDst;
	TCPDstData*	data;
	TCPData*	TData;
	TestNode*	Node;
	int		i;
	PacketRec*	p;

	DEBUGPATH;
	
	if (!Nodes)
		return FALSE;
	
	p = &Globals.Packets[PacketSlot];
	
	// get the dst out of the tcp header
	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)) {
		PRINTERROR("Failed to get TCP header data\n");
		return FALSE;
	}

	TCPDst = ntohs(TData->Header->dest);
	
	if (i == -1) {
		DBG( PRINTERROR("Couldn't find the tcp header\n") );
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp dst tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	Node = Nodes;
	while(Node) {
		if (RuleIsActive(PacketSlot, Node->RuleID)) {
			data = (TCPDstData*)Node->Data;
			if (!IsInList(data->Ports, TCPDst)) {
#ifdef DEBUGMATCH
				printf("TCP Dst %u doesn't match\n", TCPDst);
				printf("Other order is %u\n",ntohs(TCPDst));
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else {
				printf("TCP Dst Matches\n");
			}
		} else {
			printf("Rule is inactive\n");
#endif			
		}
		Node = Node->Next;
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

/**
 * Apply the TCPDst test with collapsed rules.
 */
int TestTCPDst(int PacketSlot, TestNode* Nodes)
{
	unsigned short	TCPDst;
	TCPDstData*	t;
	TCPData*	TData;
	int		i;
	PacketRec*	p;

	DEBUGPATH;
	
	if (!Nodes) 
		return FALSE;
	
	p = &Globals.Packets[PacketSlot];
	
	// get the dst out of the tcp header
	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)) {
		PRINTERROR("Failed to get TCP header data\n");
		return FALSE;
	}

	TCPDst = ntohs(TData->Header->dest);
	
	if (i == -1) {
		DBG( PRINTERROR("Couldn't find the tcp header\n") );
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp dst tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	t = TCPDstHead;
	while (t) {
		if (!IsInList(t->Ports, TCPDst)){
			/*mark these rules as inactive*/
			NotAndBitFields(p->RuleBits, t->RuleBits, p->RuleBits, Globals.NumRules);
		}
		t = t->Next;
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

/**
 * Adds a rule node to TCPDst test.
 */
int TCPDstAddNode(int TestID, int RuleID, char* Args)
{
	TCPDstData*	data;
	TCPDstData*	t;
	TCPDstData*	last;

	DEBUGPATH;

	data = calloc(sizeof(TCPDstData),1);
	
	// set up the number list
	data->Ports = InitNumList(LIST_TYPE_NORMAL);
	if (!AddRangesString(data->Ports, Args, NULL, 0)) {
		free(data);
		data = NULL;
		return FALSE;
	}
	
	// check to see if this is a duplicate
	if (!TCPDstHead) {
		DBG( PRINTERROR("First TCP Dest\n") );
		TCPDstHead = data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);
	} else {
		t = TCPDstHead;
		last = t;
		while (t) {
			if (NumListCompare(data->Ports, t->Ports)) {
				printf("This is a duplicate\n");
				DestroyNumList(data->Ports);
				free(data);
				data = NULL;
				SetBit(t->RuleBits, Globals.NumRules, RuleID, 1);
#ifdef DEBUG
				for (i = 0; i < Globals.NumRules + 1; i++)
					if (GetBit(t->RuleBits, Globals.NumRules, i))
						PRINTERROR1("Bit %i is set\n",i);
#endif				
				return TestAddNode(TestID, RuleID, (void*)t);		
			}
			
			last = t;
			t = t->Next;
		}
		
		DBG( PRINTERROR("This is a new one\n") );
		last->Next = data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);		
	}
}

/**
 * Sets up the test of the TCPDst Field.
 */
int InitTestTCPDst()
{
	int	TestID;

	DEBUGPATH;

	TCPDstHead = NULL;

	TestID = CreateTest("TCPDst");
	if (TestID == TEST_NONE)
		return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")) {
		PRINTERROR("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "dst");
	Globals.Tests[TestID].AddNode = TCPDstAddNode;
	Globals.Tests[TestID].TestFunc = TestTCPDst;
	
	TCPDecoderID = GetDecoderByName("TCP");

	return TRUE;
}
