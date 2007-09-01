/**
 * @file   test_tcp_listcontent.c
 * @author Arkanoid
 * @date   Sun Jan 22 19:42:53 2006
 * 
 * @brief  Implements the 'tcp listcontent()' test. The parameter for this
 * test in the rule file is the file name of a word list. The words are added
 * as if in a big OR statement of 'tcp content()' clauses.
 * 
 */

#include "test_tcp_listcontent.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"
#include "../engine/parse_config.h"
#include <arpa/inet.h>

extern GlobalVars	Globals;

typedef struct tcp_content_data{
	unsigned char	tcp_content[MAX_CONTENT_LEN];
} TCPListContentData;

//#define DEBUG
//#define DEBUGMATCH

int 			TCPDecoderID;
JTree			TCPListContentTree;

/** 
 * Apply the Test
 * 
 * @param PacketSlot Number of the packet in the Globals.Packets[] array
 * @param Nodes Data from the rules parameters stored for this test
 * 
 * @return TRUE if successful or FALSE in case of failure
 */
int TestTCPListContent(int PacketSlot, TestNode* Nodes){
	PacketRec*			p;
#ifdef DEBUGMATCH	
	int					i;
#endif	

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];
	
	if (!Nodes) return FALSE;
	
#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp no case tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	

	MatchStrings(&TCPListContentTree, p->RuleBits, p->RawPacket+p->BeginData, p->PacketLen - p->BeginData);
	
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
 * Add a rule node to this test
 * 
 * @param TestID Number of this test in the Globals.Tests[] array
 * @param RuleID Number of the rule in the Globals.Rules[] array
 * @param Args File name of the word list
 * 
 * @return TRUE if successful or FALSE in case of failure
 */
int TCPListContentAddNode(int TestID, int RuleID, char* Args){
	TCPListContentData*	data;
	FILE*			listf;
	char			LineBuff[10240];

	DEBUGPATH;

	listf = fopen(Args, "r");
	if (!listf){
		printf("Couldn't open file %s for 'tcp listcontent' test\n", Args);
		return FALSE;
	}

#ifdef DEBUG
	printf("Adding a Node with args from file %s\n", Args);
#endif

//			data=calloc(sizeof(TCPListContentData),1);
//			snprintf(data->tcp_content, MAX_CONTENT_LEN, "%s", Args);
	data=NULL;

	while (GetLine(listf, LineBuff, 10240)) {
#ifdef DEBUG
			printf("Adding: %s\n", LineBuff);
#endif

			if (!AddStringJTree(&TCPListContentTree, LineBuff, strlen(LineBuff), RuleID)) {
					printf("Failed to add to tree\n");
//					free(data);
//					data=NULL;
					return FALSE;
			}
	}

	fclose(listf);
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/** 
 * Called when we're all done adding rules
 * 
 * 
 * @return Result of FinalizeJTree()
 */
int TestTCPListContentFinishedSetup(){
  DEBUGPATH;

	return FinalizeJTree(&TCPListContentTree);
}


/** 
 * Set up the TCP ListContent test
 * 
 * 
 * @return TRUE if successful or FALSE in case of failure
 */
int InitTestTCPListContent() {
	int	TestID;

	DEBUGPATH;

	InitJTree(&TCPListContentTree, FALSE);

	TestID=CreateTest("TCPListContent");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "listcontent");
	Globals.Tests[TestID].AddNode=TCPListContentAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPListContent;
	Globals.Tests[TestID].FinishedSetup=TestTCPListContentFinishedSetup;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
