#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_http_method.h"
#include "../decoders/decode_http.h"
#include "../decoders/decode.h"
#include "../packets/packet.h"

extern GlobalVars	Globals;
extern int primes[MAX_PRIMES];
extern HTTPIdentifying httpi;

typedef struct http_method_data{
	int		*method;
	int		mnum;
} HTTPMethodData;

/* #define DEBUG */
/* #define DEBUGMATCH */

int HTTPDecoderID;

int TestHTTPMethod(int PacketSlot, TestNode* Nodes){
	TestNode	*Node;
	HTTPData	*http;
	HTTPMethodData	*data;
	
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
			data = (HTTPMethodData *) Node->Data;
			
			if (!BinSearch(data->method, data->mnum, http->method))
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

int HTTPMethodAddNode(int TestID, int RuleID, char* Args){
	struct node {
		int method;
		struct node *next;
	} *queue = (struct node *) calloc (sizeof(struct node), 1);

	HTTPMethodData	*data;

	int qcount = 0;
	int sum = 0;
	struct node *aux = queue;

	int i;

	DEBUGPATH;

#ifdef DEBUG
	printf("Adding a Node with args %s\n",Args);
#endif

	if (!queue) {
		fprintf (stderr, "In HTTPMethodAddNode: No memory available!\n");
		return FALSE;
	}

	for (i = 0 ; ; Args++) {
		if (*Args >= 'A' && *Args <= 'Z')
			sum += primes[i++] * *Args;
		else if (sum) {
			if (!BinSearch(httpi.method, httpi.mnum, sum)) {
				fprintf (stderr, "In HTTPMethodAddNode: Can't reconize method!\n");
				i = sum = 0;
    				continue;
			}

			aux->method = sum;
			qcount++;

			if (*Args == '\0')
				break;
			
			aux->next = (struct node *) calloc (sizeof(struct node), 1);

			if (!aux) {
				fprintf (stderr, "In HTTPMethodAddNode: No memory available!\n");
				return FALSE;
			}

			aux = aux->next;

			i = sum = 0;
		} else {
			fprintf (stderr, "In HTTPMethodAddNode: Can't reconize method!\n");
			break;
		}
	}

	if (!qcount) {
		free(queue);
		return FALSE;
	}

	data=calloc(sizeof(HTTPMethodData), 1);

	data->method = (int *) calloc (sizeof(int), qcount);
	data->mnum = qcount;

	for (aux = queue, i = 0 ; aux ; i++) {
		struct node *aux2 = aux;

		if (aux->method)
			data->method[i] = aux->method;

		aux = aux->next;

		free(aux2);
	}

	ShellSort (data->method, data->mnum);

	return TestAddNode(TestID, RuleID, (void*)data);
}

int InitTestHTTPMethod() {
	int TestID;

	DEBUGPATH;

	TestID=CreateTest("HTTPMethod");
	if (TestID==TEST_NONE) return FALSE;

	if (!BindTestToDecoder(TestID, "HTTP")){
		printf("Failed to Bind to HTTP\n");
		return FALSE;
	}

	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "method");
	Globals.Tests[TestID].AddNode=HTTPMethodAddNode;
	Globals.Tests[TestID].TestFunc=TestHTTPMethod;

	HTTPDecoderID=GetDecoderByName("HTTP");

	return TRUE;
}

