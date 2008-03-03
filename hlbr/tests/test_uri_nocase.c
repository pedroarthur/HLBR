#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "test_uri_nocase.h"
#include "../decoders/decode_uri.h"
#include "../packets/packet.h"
#include "../engine/jtree.h"

extern GlobalVars	Globals;

typedef struct uri_nocase_data{
	unsigned char	uri_content[MAX_CONTENT_LEN];
} URINoCaseData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int 	URIDecoderID;
JTree	URINoCaseTree;

/******************************************
* Apply the Test
******************************************/
int TestURINoCase(int PacketSlot, TestNode* Nodes){
	URIData		*uri;
	URINoCaseData	*data;

#ifdef DEBUGMATCH	
	int					i;
#endif	

	DEBUGPATH;

#ifdef DEBUG
	printf("Testing URI NoCase\n");
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

	GetDataByID (PacketSlot, URIDecoderID, (void **)&uri);

	MatchStrings(&URINoCaseTree, Globals.Packets[PacketSlot].RuleBits, uri->decoded, uri->decoded_size);

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
int URINoCaseAddNode(int TestID, int RuleID, char* Args){
	URINoCaseData*		data;

	DEBUGPATH;

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(URINoCaseData),1);
	snprintf(data->uri_content, MAX_CONTENT_LEN, "%s", Args);

	if (!AddStringJTree(&URINoCaseTree, Args, strlen(Args), RuleID)){
		printf("Failed to add to tree\n");
		free(data);
		data=NULL;
		return FALSE;
	}
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

int TestURINoCaseFinishedSetup(){
	DEBUGPATH;

	return FinalizeJTree(&URINoCaseTree);
}

int InitTestURINoCase(){
	int	TestID;

	DEBUGPATH;

	InitJTree(&URINoCaseTree, TRUE);

	TestID=CreateTest("URINoCase");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "URI")){
		printf("Failed to Bind to URI\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "nocase");
	Globals.Tests[TestID].AddNode=URINoCaseAddNode;
	Globals.Tests[TestID].TestFunc=TestURINoCase;
	Globals.Tests[TestID].FinishedSetup=TestURINoCaseFinishedSetup;
	
	URIDecoderID=GetDecoderByName("URI");

	return TRUE;
}
