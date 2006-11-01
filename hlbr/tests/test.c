#include "test.h"
#include "../engine/bits.h"
#include "../decoders/decode.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**********************************
* Put all the test includes here
**********************************/
#include "test_interface_name.h"
#include "test_ethernet_type.h"
#include "test_ethernet_src.h"
#include "test_ethernet_dst.h"
#include "test_ip_src.h"
#include "test_ip_dst.h"
#include "test_ip_proto.h"
#include "test_ip_ttl.h"
#include "test_icmp_type.h"
#include "test_icmp_code.h"
#include "test_tcp_port.h"
#include "test_tcp_src.h"
#include "test_tcp_dst.h"
#include "test_tcp_content.h"
#include "test_tcp_nocase.h"
#include "test_tcp_listcontent.h"
#include "test_tcp_listnocase.h"
#include "test_tcp_flags.h"
#include "test_tcp_offset.h"
#include "test_tcp_regex.h"
#include "test_udp_regex.h"
#include "test_udp_src.h"
#include "test_udp_dst.h"
//#include "test_dns_numquestions.h"
#include "test_udp_content.h"
#include "test_udp_nocase.h"

extern GlobalVars	Globals;

//#define DEBUG
#define DEBUG1

/**
 * Add all the tests to the tree
 * Calls every test's initializer function (every test must have one and have
 * it declared here)
 */
int InitTests()
{
#ifdef DEBUGPATH
	printf("In InitTests\n");
#endif

	if (!InitTestInterfaceName()) return FALSE;
	if (!InitTestEthernetType()) return FALSE;
	if (!InitTestEthernetSrc()) return FALSE;
	if (!InitTestEthernetDst()) return FALSE;
	if (!InitTestIPSrc()) return FALSE;
	if (!InitTestIPDst()) return FALSE;
	if (!InitTestIPProto()) return FALSE;
	if (!InitTestIPTTL()) return FALSE;
	if (!InitTestICMPType()) return FALSE;
	if (!InitTestICMPCode()) return FALSE;
	if (!InitTestTCPPort()) return FALSE;	
	if (!InitTestTCPSrc()) return FALSE;
	if (!InitTestTCPDst()) return FALSE;
	if (!InitTestTCPContent()) return FALSE;
	if (!InitTestTCPNoCase()) return FALSE;	
	if (!InitTestTCPListContent()) return FALSE;	
	if (!InitTestTCPListNoCase()) return FALSE;	
	if (!InitTestTCPFlags()) return FALSE;	
	if (!InitTestTCPOffset()) return FALSE;
	if (!InitTestTCPRegExp()) return FALSE;
        if (!InitTestUDPRegExp()) return FALSE;
	if (!InitTestUDPSrc()) return FALSE;
	if (!InitTestUDPDst()) return FALSE;
//	if (!InitTestDNSNumQ()) return FALSE;
	if (!InitTestUDPContent()) return FALSE;
	if (!InitTestUDPNoCase()) return FALSE;

	return TRUE;
}

/*************************************
* Given a name, return the test ID
*************************************/
int	GetTestByName(char* Name){
	int	i;

#ifdef DEBUGPATH
	printf("In GetTestByName\n");
#endif

	for (i=0;i<Globals.NumTests;i++)
		if (strcasecmp(Name, Globals.Tests[i].Name)==0) return i;

	return TEST_NONE;
}

/**************************************
* Allocate a test
**************************************/
int CreateTest(char* Name){
	int		TestID;
	
#ifdef DEBUGPATH
	printf("In CreateTest\n");
#endif	

	
	TestID=GetTestByName(Name);
	if (TestID!=TEST_NONE){	
		printf("There is already a test named %s\n",Name);
		return TEST_NONE;
	}
	
	TestID=Globals.NumTests;
	Globals.NumTests++;
	
	snprintf(Globals.Tests[TestID].Name, MAX_NAME_LEN, "%s", Name);
	Globals.Tests[TestID].ID=TestID;
	
#ifdef DEBUG
	printf("Allocating test \"%s\" in number %i\n",Globals.Tests[TestID].Name, TestID);	
#endif	

	return TestID;
}

/**************************************************
* Bind a test to a decoder
**************************************************/
int BindTestToDecoder(int TestID, char* Decoder){
	int DecoderID;
	
#ifdef DEBUGPATH
	printf("In BindTestToDecoder\n");
#endif

	DecoderID=GetDecoderByName(Decoder);
	Globals.Tests[TestID].DecoderID=DecoderID;
	if (DecoderID==DECODER_NONE) return FALSE;

	return DecoderAddTest(DecoderID, TestID);
}

/****************************************************
* Add a dependency to the decoder
* If a decoder fails, all the dependencies fail also
* Used for fast pruning
****************************************************/
int TestSetDependency(int TestID, int RuleID){
#ifdef DEBUGPATH
	printf("In TestSetDependency\n");
#endif
	
	if (TestID > Globals.NumTests) return FALSE;
	
	SetBit(Globals.Tests[TestID].DependencyMask, Globals.NumRules, RuleID, 1);

	return TRUE;
}


/*********************************************************
* Add a node to the given test
**********************************************************/
int TestAddNode(int TestID, int RuleNum, void* Data){
	TestNode*	Node;
	TestNode*	New;
	DecoderRec*	Decoder;

#ifdef DEBUGPATH
	printf("In TestAddNode\n");
#endif	
	
	New=(TestNode*)calloc(sizeof(TestNode),1);
	New->RuleID=RuleNum;
	New->Data=Data;
	
	if (!Globals.Tests[TestID].TestNodes){
		Globals.Tests[TestID].TestNodes=New;
	}else{
		Node=Globals.Tests[TestID].TestNodes;
		while (Node->Next) Node=Node->Next;
		Node->Next=New;
	}	
	
	/*mark the test and decoder as active*/
#ifdef DEBUG
	printf("Marking test \"%s\" as active\n",Globals.Tests[TestID].Name);
#endif	
	Globals.Tests[TestID].Active=TRUE;
	TestSetDependency(TestID, RuleNum);
	
	Decoder=&Globals.Decoders[Globals.Tests[TestID].DecoderID];
	while (Decoder){
#ifdef DEBUG
		printf("Marking Decoder \"%s\" as active\n", Decoder->Name);
#endif	
		Decoder->Active=TRUE;	
		DecoderSetDependency(Decoder->ID, RuleNum);
		Decoder=Decoder->Parent;
	}
		
	return TRUE;
}

/**********************************
* Let all the tests know we're
* finished adding rules
**********************************/
int TestsFinishSetup(){
	int	i;
	
#ifdef DEBUGPATH
	printf("In TestsFinishSetup\n");
#endif

	for (i=0;i<Globals.NumTests;i++){
		if (Globals.Tests[i].FinishedSetup) Globals.Tests[i].FinishedSetup();
	}
	
	return TRUE;
}
