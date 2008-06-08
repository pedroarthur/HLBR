#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "test_tcp_content.h"
#include "../decoders/decode_http.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"

extern GlobalVars	Globals;

typedef struct http_content_data{
	unsigned char	http_content[MAX_CONTENT_LEN];
} HTTPContentData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int	HTTPDecoderID;
JTree	HTTPContentTree;

int TestHTTPContent(int PacketSlot, TestNode* Nodes){
	HTTPData		*http;

#ifdef DEBUGMATCH	
	int		i;
#endif	

	DEBUGPATH;

#ifdef DEBUG
	printf("Testing HTTP Content\n");
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

	GetDataByID (PacketSlot, HTTPDecoderID, (void **)&http);

	MatchStrings(&HTTPContentTree, Globals.Packets[PacketSlot].RuleBits, http->decoded, http->decoded_size);

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

int HTTPContentAddNode(int TestID, int RuleID, char* Args){
	HTTPContentData*		data;

	DEBUGPATH;

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(HTTPContentData),1);
	snprintf(data->http_content, MAX_CONTENT_LEN, Args);

	if (!AddStringJTree(&HTTPContentTree, Args, strlen(Args), RuleID)){
		printf("Failed to add to tree\n");
		free(data);
		data=NULL;
		return FALSE;
	}

	return TestAddNode(TestID, RuleID, (void*)data);
}

int TestHTTPContentFinishedSetup(){
	DEBUGPATH;

	return FinalizeJTree(&HTTPContentTree);
}

int InitTestHTTPContent(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&HTTPContentTree, FALSE);

	TestID=CreateTest("HTTPContent");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "HTTP")){
		printf("Failed to Bind to HTTP\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "content");
	Globals.Tests[TestID].AddNode=HTTPContentAddNode;
	Globals.Tests[TestID].TestFunc=TestHTTPContent;
	Globals.Tests[TestID].FinishedSetup=TestHTTPContentFinishedSetup;

	HTTPDecoderID=GetDecoderByName("HTTP");

	return TRUE;
}
