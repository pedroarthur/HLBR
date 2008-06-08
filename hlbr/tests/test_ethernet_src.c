#include "test_ethernet_src.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ethernet.h"
#include "../packets/packet.h"

extern GlobalVars	Globals;

typedef struct ethernet_src_data{
	unsigned char	EthernetSrc[6];
} EthernetSrcData;

//#define DEBUG
//#define DEBUGMATCH
#define NEWSTYLE

int EthernetDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestEthernetSrc(int PacketSlot, TestNode* Nodes){
	unsigned char 		ESrc[6];
	EthernetSrcData*	data;
	EthernetData*		EData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

	DEBUGPATH;
	
	p=&Globals.Packets[PacketSlot];	
	
	/*get the src out of the ethernet header*/
	/*todo: make this more efficient*/
#ifndef NEWSTYLE
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==EthernetDecoderID){
			EData=(EthernetData*)p->DecoderInfo[i].Data;
			ESrc[0]=EData->Header->SrcMac[0];
			ESrc[1]=EData->Header->SrcMac[1];
			ESrc[2]=EData->Header->SrcMac[2];
			ESrc[3]=EData->Header->SrcMac[3];
			ESrc[4]=EData->Header->SrcMac[4];
			ESrc[5]=EData->Header->SrcMac[5];
			break;
		}
	}
	
	if (i==-1){
#ifdef DEBUG
		printf("Couldn't find the ethernet header\n");
#endif
		return FALSE;
	}
#else
	if (!GetDataByID(PacketSlot, EthernetDecoderID, (void **)&EData)) {
#ifdef DEBUG
		printf ("Couldn't find the ethernet header\n");
#endif
		return FALSE;
	}

	memcpy (ESrc, EData->Header->SrcMac, 6);
#endif

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
			data=(EthernetSrcData*)Node->Data;
			if (memcmp(data->EthernetSrc,ESrc,6)!=0){
#ifdef DEBUGMATCH
				printf("Ethernet Src %02x:%02x:%02x:%02x:%02x:%02x does not match test value %02x:%02x:%02x:%02x:%02x:%02x\n",
					ESrc[0],ESrc[1],ESrc[2],ESrc[3],ESrc[4],ESrc[5],
					data->EthernetSrc[0],
					data->EthernetSrc[1],
					data->EthernetSrc[2],
					data->EthernetSrc[3],
					data->EthernetSrc[4],
					data->EthernetSrc[5]
					);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("Ethernet Src Matches\n");
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
int EthernetSrcAddNode(int TestID, int RuleID, char* Args){
	int 				i;
	EthernetSrcData*	data;
	unsigned char		byte;
	char*				next_byte;
	char*				next_delim;
	
	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );

	data=calloc(sizeof(EthernetSrcData),1);	
	
	for (i=0;i<6;i++){
		next_delim=&Args[(i*3)+2];
		if ((*next_delim !=':') && (*next_delim!=0x00)){
			printf("Expected :\n");
			return FALSE;
		}
		*next_delim=0x00;
		next_byte=&Args[i*3];
		byte=strtoul(next_byte, NULL, 16);
		data->EthernetSrc[i]=byte;
	}		
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the Ethernet Src Field
*****************************************/
int InitTestEthernetSrc(){
	int	TestID;

	DEBUGPATH;

	TestID=CreateTest("EthernetSrc");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "Ethernet")){
		printf("Failed to Bind to Ethernet\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "src");
	Globals.Tests[TestID].AddNode=EthernetSrcAddNode;
	Globals.Tests[TestID].TestFunc=TestEthernetSrc;
	
	EthernetDecoderID=GetDecoderByName("Ethernet");

	return TRUE;
}

#ifdef NEWSTYLE
#undef NEWSTYLE
#endif
