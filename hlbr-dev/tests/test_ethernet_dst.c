#include "test_ethernet_dst.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_ethernet.h"
#include "../packets/packet.h"

extern GlobalVars	Globals;

typedef struct ethernet_dst_data{
	unsigned char	EthernetDst[6];
} EthernetDstData;

//#define DEBUG
//#define DEBUGMATCH

int EthernetDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestEthernetDst(int PacketSlot, TestNode* Nodes){
	unsigned char 		EDst[6];
	EthernetDstData*	data;
	EthernetData*		EData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;

#ifdef DEBUGPATH
	printf("In TestEthernetDst\n");
#endif

#ifdef DEBUG
	printf("Testing Ethernet Dst\n");
#endif	
	
	p=&Globals.Packets[PacketSlot];
	
	/*get the dst out of the ethernet header*/
	/*todo: make this more efficient*/
	for (i=p->NumDecoderData; i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==EthernetDecoderID){
			EData=(EthernetData*)p->DecoderInfo[i].Data;
			EDst[0]=EData->Header->DstMac[0];
			EDst[1]=EData->Header->DstMac[1];
			EDst[2]=EData->Header->DstMac[2];
			EDst[3]=EData->Header->DstMac[3];
			EDst[4]=EData->Header->DstMac[4];
			EDst[5]=EData->Header->DstMac[5];
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
			data=(EthernetDstData*)Node->Data;
			if (memcmp(data->EthernetDst,EDst,6)!=0){
#ifdef DEBUGMATCH
				printf("Ethernet Dst %02x:%02x:%02x:%02x:%02x:%02x does not match test value %02x:%02x:%02x:%02x:%02x:%02x\n",
					EDst[0],EDst[1],EDst[2],EDst[3],EDst[4],EDst[5],
					data->EthernetDst[0],
					data->EthernetDst[1],
					data->EthernetDst[2],
					data->EthernetDst[3],
					data->EthernetDst[4],
					data->EthernetDst[5]
					);
#endif			
				SetRuleInactive(PacketSlot, Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("Ethernet Dst Matches\n");
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
int EthernetDstAddNode(int TestID, int RuleID, char* Args){
	int 				i;
	EthernetDstData*	data;
	unsigned char		byte;
	char*				next_byte;
	char*				next_delim;
	
#ifdef DEBUGPATH
	printf("In EthernetDstAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(EthernetDstData),1);	
	
	for (i=0;i<6;i++){
		next_delim=&Args[(i*3)+2];
		if ((*next_delim !=':') && (*next_delim!=0x00)){
			printf("Expected :\n");
			return FALSE;
		}
		*next_delim=0x00;
		next_byte=&Args[i*3];
		byte=strtoul(next_byte, NULL, 16);
		data->EthernetDst[i]=byte;
	}		
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the Ethernet Dst Field
*****************************************/
int InitTestEthernetDst(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestInterfaceName\n");
#endif

	TestID=CreateTest("EthernetDst");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "Ethernet")){
		printf("Failed to Bind to Ethernet\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "dst");
	Globals.Tests[TestID].AddNode=EthernetDstAddNode;
	Globals.Tests[TestID].TestFunc=TestEthernetDst;
	
	EthernetDecoderID=GetDecoderByName("Ethernet");

	return TRUE;
}
