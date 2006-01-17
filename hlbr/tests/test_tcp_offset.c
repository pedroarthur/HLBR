#include "test_tcp_offset.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../decoders/decode_tcp.h"
#include "../packets/packet.h"
#include <arpa/inet.h>
#include "../engine/num_list.h"

extern GlobalVars	Globals;

typedef struct tcp_offset_data{
	int				offset;
	unsigned char*	string;
	int				string_len;
} TCPOffsetData;

//#define DEBUG
//#define DEBUGMATCH

int TCPDecoderID;

/******************************************
* Apply the Test
******************************************/
int TestTCPOffset(int PacketSlot, TestNode* Nodes){
	TCPData*			TData;
	TCPOffsetData*		TOData;
	TestNode*			Node;
	int					i;
	PacketRec*			p;
	
#ifdef DEBUGPATH
	printf("In TestTCPOffset\n");
#endif

#ifdef DEBUG
	printf("Testing TCP Offset\n");
#endif	

	p=&Globals.Packets[PacketSlot];

	/*TODO: Find a better way to hand this off*/
	for (i=0;i<p->NumDecoderData;i++){
		if (p->DecoderInfo[i].DecoderID==TCPDecoderID){
			TData=(TCPData*)p->DecoderInfo[i].Data;
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
			TOData=(TCPOffsetData*)Node->Data;
		
			if (TOData->string_len <= TData->DataLen)
			if (memcmp(&TData->Data[TOData->offset],TOData->string, TOData->string_len)!=0){
#ifdef DEBUGMATCH			
				printf("Tcp Offset Doesn't Match\n");
#endif				
				SetRuleInactive(PacketSlot,Node->RuleID);
			}
#ifdef DEBUGMATCH			
			else{
				printf("TCP offset Matches\n");
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
* format is offset(offset, string)
******************************************/
int TCPOffsetAddNode(int TestID, int RuleID, char* Args){
	TCPOffsetData*			data;
	unsigned char*			c;
	unsigned char*			c1;
	unsigned char			Buff[1600+1];
	int						BuffLen;
	int						i;
	int						IsBinary;
	
	char					BinBuff[6];
	int						BinChar;
	int						SLen;

#ifdef DEBUGPATH
	printf("In TCPOffsetAddNode\n");
#endif

#ifdef DEBUG
	printf("Addding a Node with args %s\n",Args);
#endif

	data=calloc(sizeof(TCPOffsetData), 1);
	
	c=Args;
	while (*c==' ') c++;
	
	c1=c+1;
	while ((*c1!=',') && (*c1)) c1++;
	if (!*c1) return FALSE;
	*c1=0x00;
	
	data->offset=atoi(c);
#ifdef DEBUG
	printf("Offset is %i\n",data->offset);
#endif	

	c1++;
	SLen=strlen(c1);
	/*apply the escape decoding*/
	IsBinary=FALSE;
	BuffLen=0;
	for (i=0;i<SLen;i++){
		if (c1[i]==0x00) break;
		if (c1[i]=='|'){
			if (c1[i+1]=='|'){
#ifdef DEBUG
				printf("Literal Pipe\n");
#endif			
				Buff[BuffLen]='|';
				BuffLen++;
			}else{
				if (IsBinary){
#ifdef DEBUG
					printf("Switching to text mode\n");
#endif
					IsBinary=FALSE;
				}else{
#ifdef DEBUG
					printf("Switching to binary mode\n");
#endif					
					IsBinary=TRUE;
				}
			}
		}else{
			if (IsBinary){
				while (c1[i]==' ') i++;
				if (c1[i]==0x00){
					printf("Unexpected end of string. Expected |\n");
					return FALSE;
				}
				
				BinBuff[0]=c1[i];
				BinBuff[1]=c1[i+1];
				BinBuff[2]=0x00;
				
				if ( (BinBuff[0]=='|') || (BinBuff[1]=='|')){
					printf("Parse Error \"%s\"\n",BinBuff);
					return FALSE;
				}
				
								
				BinChar=strtoul(BinBuff, NULL, 16);
				
#ifdef DEBUG
				printf("Adding binary character %02X\n",BinChar);
#endif				
				Buff[BuffLen]=BinChar;

				BuffLen++;
				i++;
			}else{
#ifdef DEBUG
				printf("Adding literal character %c\n",c1[i]);
#endif					
				Buff[BuffLen]=c1[i];
				BuffLen++;
			}
		}
	}

#ifdef DEBUG
	printf("Buff is %s\n",Buff);
	printf("BuffLen is %i\n", BuffLen);
#endif						
	
	data->string_len=BuffLen;
	data->string=calloc(BuffLen+1,1);
	memcpy(data->string, Buff, BuffLen);
	
	return TestAddNode(TestID, RuleID, (void*)data);
}

/****************************************
* Set up the test of the TCP Offset Field
*****************************************/
int InitTestTCPOffset(){
	int	TestID;

#ifdef DEBUGPATH
	printf("In InitTestTCPOffset\n");
#endif

	TestID=CreateTest("TCPOffset");
	if (TestID==TEST_NONE) return FALSE;
	
	if (!BindTestToDecoder(TestID, "TCP")){
		printf("Failed to Bind to TCP\n");
		return FALSE;
	} 
	
	snprintf(Globals.Tests[TestID].ShortName, MAX_NAME_LEN, "offset");
	Globals.Tests[TestID].AddNode=TCPOffsetAddNode;
	Globals.Tests[TestID].TestFunc=TestTCPOffset;
	
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
