#include "test_udp_content.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct udp_content_data{
	unsigned char	udp_content[MAX_CONTENT_LEN];
} UDPContentData;

//#define DEBUG
//#define DEBUGMATCH

int 			UDPDecoderID;
JTree			UDPContentTree;

#ifdef OLD_MATCH
/********************************************
* Returns TRUE is Candidate is in Packet
********************************************/
int MatchString(char* Candidate, int CLen, char* Packet, int PLen){
	int 	i;
	int		j;

	DEBUGPATH;

	if (CLen<PLen) return FALSE;
	
	for (i=0;i<PLen-CLen+1;i++){
		if (Packet[i]==Candidate[0]){
			for (j=1;j<CLen-1;j++){
				if (Packet[j+i]!=Candidate[j]) break;
			}
			if (j==(CLen-1)) return TRUE;
		}
	}

	return FALSE;
}
#endif

/******************************************
* Apply the Test
******************************************/
int TestUDPContent(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
#ifdef DEBUGMATCH	
	int					i;
#endif	

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying udp content tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	

	MatchStrings(&UDPContentTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
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
int UDPContentAddNode(int TestID, int RuleID, char* Args){
	UDPContentData*		data;

	DEBUGPATH;

	DBG( PRINT1("Addding a Node with args %s\n",Args) );

	data=calloc(sizeof(UDPContentData),1);
	snprintf(data->udp_content, MAX_CONTENT_LEN, Args);

	if (!AddStringJTree(&UDPContentTree, Args, strlen(Args), RuleID)){
		printf("Failed to add to tree\n");
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Called when we're all done adding rules
****************************************/
int TestUDPContentFinishedSetup(){
  DEBUGPATH;

	return FinalizeJTree(&UDPContentTree);
}

/****************************************
* Set up the test of the UDP Content
*****************************************/
int InitTestUDPContent(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&UDPContentTree, FALSE);

	TestID=CreateTest("UDPContent");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "UDP")){
		printf("Failed to Bind to UDP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "content");
	Globals.Tests[TestID].AddNode=UDPContentAddNode;
	Globals.Tests[TestID].TestFunc=TestUDPContent;
	Globals.Tests[TestID].FinishedSetup=TestUDPContentFinishedSetup;
	
	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
