#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "test_http_nocase.h"
#include "../decoders/decode_http.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"

extern GlobalVars	Globals;

typedef struct http_nocase_data{
	unsigned char	http_content[MAX_CONTENT_LEN];
} HTTPNoCaseData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int 	HTTPDecoderID;
JTree	HTTPNoCaseTree;

/******************************************
* Apply the Test
******************************************/
int TestHTTPNoCase(int PacketSlot, TestNode* Nodes){
	HTTPData		*http;
	HTTPNoCaseData	*data;

#ifdef DEBUGMATCH	
	int					i;
#endif	

	DEBUGPATH;

#ifdef DEBUG
	printf("Testing HTTP NoCase\n");
#endif	

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

	GetDataByID (PacketSlot, HTTPDecoderID, (void **)&http);

	MatchStrings(&HTTPNoCaseTree, Globals.Packets[PacketSlot].RuleBits, http->decoded, http->decoded_size);

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
int HTTPNoCaseAddNode(int TestID, int RuleID, char* Args){
	HTTPNoCaseData*		data;

	DEBUGPATH;

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(HTTPNoCaseData),1);
	snprintf(data->http_content, MAX_CONTENT_LEN, "%s", Args);

	if (!AddStringJTree(&HTTPNoCaseTree, Args, strlen(Args), RuleID)){
		printf("Failed to add to tree\n");
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

int TestHTTPNoCaseFinishedSetup(){
	DEBUGPATH;

	return FinalizeJTree(&HTTPNoCaseTree);
}

int InitTestHTTPNoCase(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&HTTPNoCaseTree, TRUE);

	TestID=CreateTest("HTTPNoCase");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "HTTP")){
		printf("Failed to Bind to HTTP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "nocase");
	Globals.Tests[TestID].AddNode=HTTPNoCaseAddNode;
	Globals.Tests[TestID].TestFunc=TestHTTPNoCase;
	Globals.Tests[TestID].FinishedSetup=TestHTTPNoCaseFinishedSetup;
	
	HTTPDecoderID=GetDecoderByName("HTTP");

	return TRUE;
}
