#include "test_tcp_flags.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"
#include "../engine/bits.h"

extern GlobalVars	Globals;

typedef struct tcp_flags_data{
	char	Fin;
	char	Syn;
	char	Rst;
	char	Psh;
	char	Ack;
	char	Urg;
	char	Ece;
	char	Cwr;
	
	unsigned char			RuleBits[MAX_RULES/8];
	struct tcp_flags_data*	Next;
} TCPFlagsData;

//#define DEBUG
//#define DEBUGMATCH

int TCPDecoderID;
TCPFlagsData*	TCPFlagsHead;

/******************************************
* Apply the Test with collapsed rules
******************************************/
int TestTCPFlags(int PacketSlot, TestNode* Nodes){
	unsigned short 		TCPFlags;
	TCPFlagsData*			t;
	TCPData*			TData;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestTCPFlags\n");
#endif

#ifdef DEBUG
	printf("Testing TCP Flag\n");
#endif	
	
	if (!Nodes) return FALSE;
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the flags out of the tcp header*/
	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)){
		printf("Failed to get TCP header data\n");
		return FALSE;
	}

	TCPFlags=ntohs(TData->Header->dest);
	
	if (i==-1){
#ifdef DEBUG	
		printf("Couldn't find the tcp header\n");
#endif		
		return FALSE;
	}

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp flags tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	
	t=TCPFlagsHead;
	while (t){
		if ( (t->Fin==0) || (t->Fin==1 && TData->Header->fin) || (t->Fin==-1 && !TData->Header->fin))
		if ( (t->Syn==0) || (t->Syn==1 && TData->Header->syn) || (t->Syn==-1 && !TData->Header->syn))
		if ( (t->Rst==0) || (t->Rst==1 && TData->Header->rst) || (t->Rst==-1 && !TData->Header->rst))
		if ( (t->Psh==0) || (t->Psh==1 && TData->Header->psh) || (t->Psh==-1 && !TData->Header->psh))
		if ( (t->Ack==0) || (t->Ack==1 && TData->Header->ack) || (t->Ack==-1 && !TData->Header->ack))
		if ( (t->Urg==0) || (t->Urg==1 && TData->Header->urg) || (t->Urg==-1 && !TData->Header->urg))
		if ( (t->Ece==0) || (t->Ece==1 && TData->Header->ece) || (t->Ece==-1 && !TData->Header->ece))
		if ( (t->Cwr==0) || (t->Cwr==1 && TData->Header->cwr) || (t->Cwr==-1 && !TData->Header->cwr)){
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
int TCPFlagsAddNode(int TestID, int RuleID, char* Args){
	TCPFlagsData*			data;
	TCPFlagsData*			t;
	TCPFlagsData*			last;
#ifdef DEBUG	
	int						i;
#endif	

#ifdef DEBUGPATH
	printf("In TCPFlagsAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(TCPFlagsData),1);
	
	while (*Args){
		switch (*Args){
		case 'f':
			data->Fin=-1;
			break;
		case 'F':
			data->Fin=1;
			break;
		case 's':
			data->Syn=-1;
			break;
		case 'S':
			data->Syn=1;
			break;
		case 'r':
			data->Rst=-1;
			break;
		case 'R':
			data->Rst=1;
			break;
		case 'p':
			data->Psh=-1;
			break;
		case 'P':
			data->Psh=1;
			break;
		case 'a':
			data->Ack=-1;
			break;
		case 'A':
			data->Ack=1;
			break;
		case 'u':
			data->Urg=-1;
			break;
		case 'U':
			data->Urg=1;
			break;
		case 'e':
			data->Ece=-1;
			break;
		case 'E':
			data->Ece=1;
			break;
		case 'c':
			data->Cwr=-1;
			break;
		case 'C':
			data->Cwr=1;
			break;
		case ' ':
		case '*':
			break;
		default:
			printf("Unknown TCP flag \"%c\"\n",*Args);
			return FALSE;
		}
		Args++;
	}

	/*check to see if this is a duplicate*/
	if (!TCPFlagsHead){
#ifdef DEBUG
		printf("First TCP Flag\n");
#endif	
		TCPFlagsHead=data;
		SetBit(data->RuleBits, Globals.NumRules, RuleID, 1);
		return TestAddNode(TestID, RuleID, (void*)data);
	}else{
		t=TCPFlagsHead;
		last=t;
		while (t){
			if (
				(t->Fin == data->Fin) && 
				(t->Syn == data->Syn) && 
				(t->Rst == data->Rst) && 
				(t->Psh == data->Psh) && 
				(t->Ack == data->Ack) && 
				(t->Urg == data->Urg) && 
				(t->Ece == data->Ece) && 
				(t->Cwr == data->Cwr)
			){
#ifdef DEBUG
				printf("This is a duplicate\n");
#endif			
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
* Set up the test of the TCP Flags Field
*****************************************/
int InitTestTCPFlags(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestTCPFlags\n");
#endif

	TCPFlagsHead=NULL;

	TestID=CreateTest("TCPFlags");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "flags");
	Globals.Tests[TestID].AddNode=TCPFlagsAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPFlags;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
