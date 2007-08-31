#include "test_udp_regex.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include <pcre.h>

extern GlobalVars	Globals;

typedef struct udp_regexp_data{
	unsigned char	udp_content[MAX_CONTENT_LEN];
	pcre		*re;
	pcre_extra	*ere;
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
			pcre *re;

			/* 
			 * Please refer to file test_tcp_regex.c for some
			 * comments about the changes i've made. 
			 * 
			 * */

#ifdef DEBUGMATCH
			char regex_str[50];
#endif
			data=(UDPRegExpData*)Node->Data;

			// string = (p->RawPacket + p->BeginData);

#ifdef DEBUGMATCH
			if (pcre_exec(data->re, data->ere, p->RawPacket + p->BeginData, p->PacketLen - p->BeginData, 0, PCRE_NOTEMPTY, regex_str, 50) < 0) {
				printf ("%s\n", regex_str);
#else
			if (pcre_exec(data->re, data->ere, p->RawPacket + p->BeginData, p->PacketLen - p->BeginData, 0, PCRE_NOTEMPTY, NULL, 0) < 0)
#endif
				SetRuleInactive(PacketSlot, Node->RuleID);
#ifdef DEBUGMATCH
			}
#endif
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
	int errocode;
	int erofset;
	const char *errors;

#ifdef DEBUGPATH
	printf("In UDPRegExpAddNode\n");
#endif

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(UDPRegExpData),1);
	snprintf(data->udp_content, MAX_CONTENT_LEN, "%s", Args);

	data->re = pcre_compile(data->udp_content, PCRE_MULTILINE, &errors, &erofset, NULL);

	if (errocode) {
		printf ("Regular Expression Parse Error: TestID=%d RuleID=%d Args=%s Errocode=%d Error=\"%s\"\n"\
				, TestID, RuleID, Args, errocode, errors);
		return 1;
	}

	data->ere = pcre_study(data->re, 0, &errors);
	if (errors != NULL) {
		printf ("Regular Expression Parse Error: TestID=%d RuleID=%d Args=%s Error=\"%s\"\n"\
				, TestID, RuleID, Args, errors);
		return 1;
	}

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
