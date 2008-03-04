#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_uri_regex.h"
#include "../decoders/decode_uri.h"
#include "../packets/packet.h"
#include "../engine/regex.h"

extern GlobalVars	Globals;

typedef struct uri_regexp_data{
	char		content[MAX_CONTENT_LEN];
	HLBRRegex	*regex;
} URIRegExpData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int URIDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestURIRegExp(int PacketSlot, TestNode* Nodes){
	TestNode	*Node;
	URIData		*uri;
	
#ifdef DEBUGMATCH
	int i;
#endif

	DEBUGPATH;

#ifdef DEBUG
	printf("Testing URI RegExp\n");
#endif

	if (!Nodes) return FALSE;

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("Before applying uri regexp tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(PacketSlot,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif

	GetDataByID (PacketSlot, URIDecoderID, (void **)&uri);

	Node=Nodes;

	while (Node) {
		if (RuleIsActive(PacketSlot, Node->RuleID)) {
			URIRegExpData	*data = (URIRegExpData*)Node->Data;
#ifdef DEBUGMATCH
			if (!RegexExecDebug(data->regex, uri->decoded, uri->decoded_size))
#else
			if (!RegexExec(data->regex, uri->decoded, uri->decoded_size))
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

int URIRegExpAddNode(int TestID, int RuleID, char* Args){
	URIRegExpData	*data;

	DEBUGPATH;

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(URIRegExpData),1);
	snprintf(data->content, MAX_CONTENT_LEN, "%s", Args);

	data->regex = RegexCompile(data->content, MULTILINE, NOTEMPTY, 0);

	if (!data->regex)
		return FALSE;

	return TestAddNode(TestID, RuleID, (void*)data);
}

int InitTestURIRegExp() {
	int TestID;

	DEBUGPATH;

	TestID=CreateTest("URIRegExp");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "URI")){
		printf("Failed to Bind to URI\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "regex");
	Globals.Tests[TestID].AddNode=URIRegExpAddNode;
	Globals.Tests[TestID].TestFunc=TestURIRegExp;

	URIDecoderID=GetDecoderByName("URI");

	return TRUE;
}

