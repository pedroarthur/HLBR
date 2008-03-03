#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcre.h>

#include "test_uri_regex.h"
#include "../decoders/decode_uri.h"
#include "../packets/packet.h"

extern GlobalVars	Globals;

typedef struct uri_regexp_data{
	char		content[MAX_CONTENT_LEN];
	pcre		*re;
	pcre_extra	*ere;
} URIRegExpData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int URIDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestURIRegExp(int PacketSlot, TestNode* Nodes){
	TestNode	*Node;
	URIRegExpData	*data;
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
#ifdef DEBUGMATCH
			char regex_str[50];
#endif
			data=(URIRegExpData*)Node->Data;
#ifdef DEBUGMATCH
			if (pcre_exec(data->re, data->ere, uri->decoded, uri->decoded_size, 0, PCRE_NOTEMPTY, regex_str, 50) < 0) {
				printf ("%s\n", regex_str);
#else
			if (pcre_exec(data->re, data->ere, uri->decoded, uri->decoded_size, 0, PCRE_NOTEMPTY, NULL, 0) < 0)
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

int URIRegExpAddNode(int TestID, int RuleID, char* Args){
	URIRegExpData	*data;
	const char	*errors;
	int		erofset;
	int		errocode;

	DEBUGPATH;

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(URIRegExpData),1);
	snprintf(data->content, MAX_CONTENT_LEN, "%s", Args);

	data->re = pcre_compile2(data->content, PCRE_MULTILINE, &errocode, &errors, &erofset, NULL);

	if (errocode) {
		printf ("Regular Expression Parse Error: TestID=%d RuleID=%d Args=%s Errocode=%d Error-Offset=%d Error=\"%s\"\n"\
				, TestID, RuleID, Args, errocode, erofset, errors);
		return FALSE;
	}

	data->ere = pcre_study(data->re, 0, &errors);

	if (errors) {
		printf ("Regular Expression Parse Error: TestID=%d RuleID=%d Args=%s Error=\"%s\"\n"\
				, TestID, RuleID, Args, errors);
		return FALSE;
	}

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

