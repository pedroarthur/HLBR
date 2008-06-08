#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_http_regex.h"
#include "../decoders/decode_http.h"
#include "../packets/packet.h"
#include "../engine/regex.h"

extern GlobalVars	Globals;

typedef struct http_regexp_data{
	char		content[MAX_CONTENT_LEN];
	HLBRRegex	*regex;
} HTTPRegExpData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int HTTPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestHTTPRegExp(int PacketSlot, TestNode* Nodes){
	TestNode	*Node;
	HTTPData		*http;
	
#ifdef DEBUGMATCH
	int i;
#endif

	DEBUGPATH;

#ifdef DEBUG
	printf("Testing HTTP RegExp\n");
#endif

	if (!Nodes) return FALSE;

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying http regexp tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif

	GetDataByID (PacketSlot, HTTPDecoderID, (void **)&http);

	Node=Nodes;

	while (Node) {
		if (RuleIsActive(PacketSlot, Node->RuleID)) {
			HTTPRegExpData	*data = (HTTPRegExpData*)Node->Data;
#ifdef DEBUGMATCH
			if (!RegexExecDebug(data->regex, http->decoded, http->decoded_size))
#else
			if (!RegexExec(data->regex, http->decoded, http->decoded_size))
#endif
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

int HTTPRegExpAddNode(int TestID, int RuleID, char* Args){
	HTTPRegExpData	*data;

	DEBUGPATH;

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(HTTPRegExpData),1);
	snprintf(data->content, MAX_CONTENT_LEN, "%s", Args);

	data->regex = RegexCompile(data->content, MULTILINE, NOTEMPTY, 0);

	if (!data->regex)
		return FALSE;

	return TestAddNode(TestID, RuleID, (void*)data);
}

int InitTestHTTPRegExp() {
	int TestID;

	DEBUGPATH;

	TestID=CreateTest("HTTPRegExp");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "HTTP")){
		printf("Failed to Bind to HTTP\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "regex");
	Globals.Tests[TestID].AddNode=HTTPRegExpAddNode;
	Globals.Tests[TestID].TestFunc=TestHTTPRegExp;

	HTTPDecoderID=GetDecoderByName("HTTP");

	return TRUE;
}

