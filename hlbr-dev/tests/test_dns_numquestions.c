#include "test_dns_numquestions.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_udp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct udp_dns_numq_data{
	unsigned short	NumQ;
} DNSNumQData;

#define DEBUG
//#define DEBUGMATCH

int DNSDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestDNSNumQ(int PacketSlot, TestNode* Nodes){
	return TRUE;
}

/******************************************
* Add a rule node to this test
******************************************/
int DNSNumQAddNode(int TestID, int RuleID, char* Args){
	DNSNumQData*			data;

#ifdef DEBUGPATH
	printf("In DNSNumQAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(DNSNumQData),1);	
				
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the DNS NumQuestions Field
*****************************************/
int InitTestDNSNumQ(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestDNSNumQ\n");
#endif

	TestID=CreateTest("DNSNumQuestions");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "DNS")){
		printf("Failed to Bind to DNS\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "NumQ");
	Globals.Tests[TestID].AddNode=DNSNumQAddNode;
	Globals.Tests[TestID].TestFunc=TestDNSNumQ;
	
	DNSDecoderID=GetDecoderByName("DNS");

	return TRUE;
}
