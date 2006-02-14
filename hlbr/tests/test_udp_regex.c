#include "test_udp_regex.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct udp_regexp_data{
	unsigned char	udp_content[MAX_CONTENT_LEN];
	regex_t            *re;
} UDPRegExpData;

//#define DEBUG
//#define DEBUGMATCH

int UDPDecoderID;


/******************************************
* Apply the Test
******************************************/
int TestUDPRegExp(int PacketSlot, TestNode* Nodes){
	PacketRec* p;
	TestNode* Node;
	UDPRegExpData* data;
	int result;
	int i;

#ifdef DEBUGPATH
	printf("In TestUDPRegExp\n");
#endif

#ifdef DEBUG
	printf("Testing UDP RegExp\n");
#endif	

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying udp regexp tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	
	Node=Nodes;

	while (Node) {
	 
	  if (RuleIsActive(PacketSlot, Node->RuleID)) {
          	regex_t   re;

	  	data=(UDPRegExpData*)Node->Data;
	  	result=0;

	  	//regfree(&re);

		result = match(p->RawPacket+p->BeginData, data->re);

		if (result != 0)
			SetRuleInactive(PacketSlot, Node->RuleID);

	  }

                Node=Node->Next;
	
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
* Add a rule node to this tets
******************************************/
int UDPRegExpAddNode(int TestID, int RuleID, char* Args){
	UDPRegExpData* data;
	int status;

#ifdef DEBUGPATH
	printf("In UDPRegExpAddNode\n");
#endif

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(UDPRegExpData),1);
	data->re=calloc(sizeof(regex_t),1);
	snprintf(data->udp_content, MAX_CONTENT_LEN, "%s", Args);
     	
	if((status=regcomp( data->re, data->udp_content, REG_EXTENDED)) != 0)
        return(status);
	
	//data = regular expression
	return TestAddNode(TestID, RuleID, (void*)data); 
}

/****************************************
* Set up the test of the UDP RE
*****************************************/
int InitTestUDPRegExp(){
	int TestID;

#ifdef DEBUGPATH
	printf("In InitTestUDPRegExp\n");
#endif

	TestID=CreateTest("UDPRegExp");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "UDP")){
		printf("Failed to Bind to UDP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "regex");
	Globals.Tests[TestID].AddNode=UDPRegExpAddNode;
	Globals.Tests[TestID].TestFunc=TestUDPRegExp;

	
	UDPDecoderID=GetDecoderByName("UDP");

	return TRUE;
}
