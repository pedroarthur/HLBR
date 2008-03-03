#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "test_tcp_content.h"
#include "../decoders/decode_uri.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"

extern GlobalVars	Globals;

typedef struct uri_content_data{
	unsigned char	uri_content[MAX_CONTENT_LEN];
} URIContentData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int	URIDecoderID;
JTree	URIContentTree;

int TestURIContent(int PacketSlot, TestNode* Nodes){
	URIData		*uri;

#ifdef DEBUGMATCH	
	int		i;
#endif	

	DEBUGPATH;

#ifdef DEBUG
	printf("Testing URI Content\n");
#endif	

	if (!Nodes) return FALSE;

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying tcp content tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif

	GetDataByID (PacketSlot, URIDecoderID, (void **)&uri);

	MatchStrings(&URIContentTree, Globals.Packets[PacketSlot].RuleBits, uri->decoded, uri->decoded_size);

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

int URIContentAddNode(int TestID, int RuleID, char* Args){
	URIContentData*		data;

	DEBUGPATH;

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(URIContentData),1);
	snprintf(data->uri_content, MAX_CONTENT_LEN, Args);

	if (!AddStringJTree(&URIContentTree, Args, strlen(Args), RuleID)){
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
int TestURIContentFinishedSetup(){
	DEBUGPATH;

	return FinalizeJTree(&URIContentTree);
}

/****************************************
* Set up the test of the TCP Content
*****************************************/
int InitTestURIContent(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&URIContentTree, FALSE);

	TestID=CreateTest("URIContent");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "URI")){
		printf("Failed to Bind to URI\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "content");
	Globals.Tests[TestID].AddNode=URIContentAddNode;
	Globals.Tests[TestID].TestFunc=TestURIContent;
	Globals.Tests[TestID].FinishedSetup=TestURIContentFinishedSetup;

	URIDecoderID=GetDecoderByName("URI");

	return TRUE;
}
