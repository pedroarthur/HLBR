#include "test_interface_name.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_interface.h"
#include "../packets/packet.h"

extern GlobalVars	Globals;

typedef struct interface_name_data{
	int		InterfaceNum;
} InterfaceNameData;

#define DEBUG

int InterfaceDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestInterfaceName(int PacketSlot, TestNode* Nodes){
	InterfaceData*		IData;
	InterfaceNameData*	INData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;
	
#ifdef DEBUGPATH
	printf("In TestInterfaceName\n");
#endif

#ifdef DEBUG
	printf("Testing Interface Name\n");
#endif	

	p=&Globals.Packets[PacketSlot];

	/*TODO: Find a better way to hand this off*/
	for (i=0;i<p->NumDecoderData;i++){
		if (p->DecoderInfo[i].DecoderID==InterfaceDecoderID){
			IData=(InterfaceData*)p->DecoderInfo[i].Data;
		}
	}

#ifdef DEBUGMATCH
	printf("\n\n");	
	printf("**************************************\n");
	printf("Before applying interface name tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(p,i))
		printf("Rule %i is active\n",i);
	else
		printf("Rule %i is inactive\n",i);
	printf("**************************************\n");
#endif	

	Node=Nodes;
	while (Node){
		if (RuleIsActive(PacketSlot, Node->RuleID)){
			INData=(InterfaceNameData*)Node->Data;
		
			if (INData->InterfaceNum!=IData->r->ID){
#ifdef DEBUGMATCH			
				printf("Interface %s Doesn't Match\n",Globals.Interfaces[INData->InterfaceNum].Name);
#endif				
				SetRuleInactive(PacketSlot,Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("Interface %s Matches\n",Globals.Interfaces[INData->InterfaceNum].Name);
			}
#endif						
		}
#ifdef DEBUGMATCH		
		else{
			printf("Rule %i is inactive\n", Node->RuleID);
		}
#endif		
		Node=Node->Next;	
	}	

#ifdef DEBUGMATCH
	printf("**************************************\n");
	printf("After applying interface name tests\n");
	for (i=0;i<Globals.NumRules;i++)
	if (RuleIsActive(p,i))
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
int InterfaceNameAddNode(int TestID, int RuleID, char* Args){
	int 				i;
	InterfaceNameData*	data;
	
#ifdef DEBUGPATH
	printf("In InterfaceNameAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding Node with args %s\n",Args);
#endif

	/*find the interface*/
	for (i=0;i<Globals.NumInterfaces;i++){
		if (strcasecmp(Args, Globals.Interfaces[i].Name)==0){
			data=(InterfaceNameData*)calloc(sizeof(InterfaceNameData),1);
			data->InterfaceNum=i;
			return TestAddNode(TestID, RuleID, (void*)data);
		}
	}

	printf("There is no interface defined named \"%s\"\n",Args);

	return FALSE;
}

/****************************************
* Set up the test of the interface name
*****************************************/
int InitTestInterfaceName(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestInterfaceName\n");
#endif

	TestID=CreateTest("InterfaceName");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "Interface")){
		printf("Failed to Bind to Interface\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "name");
	Globals.Tests[TestID].AddNode=InterfaceNameAddNode;
	Globals.Tests[TestID].TestFunc=TestInterfaceName;
	
	InterfaceDecoderID=GetDecoderByName("Interface");

	return TRUE;
}
