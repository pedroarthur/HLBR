#include "test_udp_nocase.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct udp_nocase_data{
	unsigned char	udp_content[MAX_CONTENT_LEN];
} UDPNoCaseData;

//#define DEBUG
//#define DEBUGMATCH

int 			UDPDecoderID;
JTree			UDPNoCaseTree;

/******************************************
* Apply the Test
******************************************/
int TestUDPNoCase(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
#ifdef DEBUGMATCH	
	int					i;
#endif	

#ifdef DEBUGPATH
	printf("In TestUDPNoCase\n");
#endif

#ifdef DEBUG
	printf("Testing UDP NoCase\n");
#endif	

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying udp no case tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	

	MatchStrings(&UDPNoCaseTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
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
int UDPNoCaseAddNode(int TestID, int RuleID, char* Args){
	UDPNoCaseData*		data;

#ifdef DEBUGPATH
	printf("In UDPNoCaseAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(UDPNoCaseData),1);
	snprintf(data->udp_content, MAX_CONTENT_LEN, Args);

	if (!AddStringJTree(&UDPNoCaseTree, Args, strlen(Args), RuleID)){
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
int TestUDPNoCaseFinishedSetup(){
#ifdef DEBUGPATH
	printf("In TestUDPContentFinishedSetup\n");
#endif

	return FinalizeJTree(&UDPNoCaseTree);
}


/****************************************
* Set up the test of the UDP NoCase
*****************************************/
int InitTestUDPNoCase(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestUDPNoCase\n");
#endif

	InitJTree(&UDPNoCaseTree, TRUE);

	TestID=CreateTest("UDPNoCase");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "UDP")){
		printf("Failed to Bind to UDP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "nocase");
	Globals.Tests[TestID].AddNode=UDPNoCaseAddNode;
	Globals.Tests[TestID].TestFunc=TestUDPNoCase;
	Globals.Tests[TestID].FinishedSetup=TestUDPNoCaseFinishedSetup;
	
	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
