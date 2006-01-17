#include "mangle_hard_mac.h"
#include "../decoders/decode_ethernet.h"
#include "../decoders/decode_arp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct mangle_node{
	unsigned char 		Interface;
	unsigned char		PrivateMac[6];
	unsigned char		PublicMac[6];
	struct mangle_node*	Next;
} MangleNode;

int EthernetDecoderID;
int ARPDecoderID;
MangleNode*	MangleNodes;

extern GlobalVars Globals;

#define DEBUG


/***********************************************
* If it's going out the proper interface, change
* its destination mac address to the honeypot addr
*
* If it's comming from the honeypot interface, change
* the source mac to the production mac
***********************************************/
int MangleHardMac(int PacketSlot, int SourceInterface, int DestInterface){
	MangleNode*		Node;
	EthernetData*	EData;
	ARPData*		AData;
	PacketRec*		p;
	int				i;
	
#ifdef DEBUGPATH
	printf("In MangleHardMac\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, EthernetDecoderID, (void**)&EData)){
#ifdef DEBUG
		printf("Not an ethernet packet\n");
#endif	
		return TRUE;
	}

	if (!GetDataByID(PacketSlot, ARPDecoderID, (void**)&AData)){
#ifdef DEBUG1
		printf("Not an ARP packet\n");
#endif	
		AData=NULL;
	}

	p=&Globals.Packets[PacketSlot];

	Node=MangleNodes;
	while (Node){
	
		if ( AData && (Node->Interface==p->InterfaceNum) && (memcmp(Node->PrivateMac, AData->EthernetARPHeader->SenderMac, 6)==0) ){
#ifdef DEBUG
			printf("ARP Field 1 is being changed to public mac\n");
#endif		
			for (i=0;i<6;i++) AData->EthernetARPHeader->SenderMac[i]=Node->PublicMac[i];
		}

		if ( AData && (Node->Interface==p->InterfaceNum) && (memcmp(Node->PrivateMac, AData->EthernetARPHeader->TargetMac, 6)==0) ){
#ifdef DEBUG
			printf("ARP Field 2 is being changed to public mac\n");
#endif		
			for (i=0;i<6;i++) AData->EthernetARPHeader->TargetMac[i]=Node->PublicMac[i];
		}


		if ( AData && (Node->Interface==p->TargetInterface) && (memcmp(Node->PublicMac, AData->EthernetARPHeader->SenderMac, 6)==0) ){
#ifdef DEBUG
			printf("ARP Field 1 is being changed to private mac\n");
#endif		
			for (i=0;i<6;i++) AData->EthernetARPHeader->SenderMac[i]=Node->PrivateMac[i];
		}

		if ( AData && (Node->Interface==p->InterfaceNum) && (memcmp(Node->PublicMac, AData->EthernetARPHeader->TargetMac, 6)==0) ){
#ifdef DEBUG
			printf("ARP Field 2 is being changed to private mac\n");
#endif		
			for (i=0;i<6;i++) AData->EthernetARPHeader->TargetMac[i]=Node->PrivateMac[i];
		}

		printf("From interface %i\n",p->InterfaceNum);
		if (Node->Interface==p->InterfaceNum){
			printf("This packet is from honeypot\n");
			printf("Src Mac %02X:%02X:%02X:%02X:%02X:%02X",
				EData->Header->SrcMac[0],
				EData->Header->SrcMac[1],
				EData->Header->SrcMac[2],
				EData->Header->SrcMac[3],
				EData->Header->SrcMac[4],
				EData->Header->SrcMac[5]);
			printf("Private Mac %02X:%02X:%02X:%02X:%02X:%02X\n",
				Node->PrivateMac[0],
				Node->PrivateMac[1],
				Node->PrivateMac[2],
				Node->PrivateMac[3],
				Node->PrivateMac[4],
				Node->PrivateMac[5]);				
		}

		if ( (Node->Interface==p->InterfaceNum) && (memcmp(Node->PrivateMac, EData->Header->SrcMac, 6)==0)){
#ifdef DEBUG
			printf("This packet is comming from the honeypot\n");
			printf("Switching Src Mac from %02X:%02X:%02X:%02X:%02X:%02X",
				EData->Header->SrcMac[0],
				EData->Header->SrcMac[1],
				EData->Header->SrcMac[2],
				EData->Header->SrcMac[3],
				EData->Header->SrcMac[4],
				EData->Header->SrcMac[5]);
			printf(" to %02X:%02X:%02X:%02X:%02X:%02X\n",
				Node->PublicMac[0],
				Node->PublicMac[1],
				Node->PublicMac[2],
				Node->PublicMac[3],
				Node->PublicMac[4],
				Node->PublicMac[5]);				
#endif

			for (i=0;i<6;i++) EData->Header->SrcMac[i]=Node->PublicMac[i];
		}
		
		
		if ( (Node->Interface==p->TargetInterface) && (memcmp(Node->PublicMac, EData->Header->DstMac, 6)==0)){
#ifdef DEBUG
			printf("This packet is going to the honeypot\n");
			printf("Switching Dst Mac from %02X:%02X:%02X:%02X:%02X:%02X",
				EData->Header->DstMac[0],
				EData->Header->DstMac[1],
				EData->Header->DstMac[2],
				EData->Header->DstMac[3],
				EData->Header->DstMac[4],
				EData->Header->DstMac[5]);
			printf(" to %02X:%02X:%02X:%02X:%02X:%02X\n",
				Node->PrivateMac[0],
				Node->PrivateMac[1],
				Node->PrivateMac[2],
				Node->PrivateMac[3],
				Node->PrivateMac[4],
				Node->PrivateMac[5]);				
#endif

			for (i=0;i<6;i++) EData->Header->DstMac[i]=Node->PrivateMac[i];
		}		

		Node=Node->Next;
	}

	return TRUE;
}

/**********************************************
* Add another mangler to the list
***********************************************/
int MangleHardMacAddNode(int MangleID, char* Args){
	int			InterfaceNum;
	char*		sp;
	int			i;
	MangleNode*	mn;
	MangleNode* t;
	char		Buff[16];
	
#ifdef DEBUGPATH
	printf("In MangleHardMacAddNode\n");
#endif

	if (!Args){
		printf("Format:\n");
		printf("HardMac interface, private MAC, public MAC\n");
		printf("Example eth2, 01:02:03:04:05:06, 11:12:13:14:15:16\n");
		
		return FALSE;
	}
	
	mn=(MangleNode*)calloc(sizeof(MangleNode),1);
	
	/*first get the interface*/
	sp=strchr(Args, ',');
	if (!sp){
		printf("Expected Interface Name\n");
		return FALSE;
	}
	
	*sp=0x00;
	sp++;
	while (*sp==' ') sp++;
	if (sp==0x00){
		printf("Expected Private MAC\n");
		return FALSE;	
	}
	
	/*see if that interface exists*/
#ifdef DEBUG
	printf("Searching for interface \"%s\"\n",Args);
#endif	
	for (i=0;i<Globals.NumInterfaces;i++){
		if (strcasecmp(Args, Globals.Interfaces[i].Name)==0){
			InterfaceNum=i;
			break;
		}
	}

	if (i==Globals.NumInterfaces){
		printf("Unknown Interface \"%s\"\n",Args);
		return FALSE;
	}

	mn->Interface=InterfaceNum;

#ifdef DEBUG
	printf("Mangle interface set to %i(%s)\n",mn->Interface, Globals.Interfaces[mn->Interface].Name);
#endif

	for (i=0;i<6;i++){
		Buff[0]=*sp;
		Buff[1]=*(sp+1);
		Buff[2]=0x00;
		
		if ((*(sp+2)!=':') && (i!=5)){
			printf("Expected Mac Address in format 01:02:03:04:05:06\n");
			return FALSE;
		}
		
		mn->PrivateMac[i]=strtoul(Buff, NULL, 16);

		sp+=3;
	}

#ifdef DEBUG
	printf("Private MAC is %02X:%02X:%02X:%02X:%02X:%02X\n",
		mn->PrivateMac[0],
		mn->PrivateMac[1],
		mn->PrivateMac[2],
		mn->PrivateMac[3],
		mn->PrivateMac[4],
		mn->PrivateMac[5]);
#endif

	while (((*sp==' ') || (*sp==',')) && (*sp)) sp++;
	
	if (!sp){
		printf("Expected Public Mac\n");
		return FALSE;
	}

	for (i=0;i<6;i++){
		Buff[0]=*sp;
		Buff[1]=*(sp+1);
		Buff[2]=0x00;
		
		if ((*(sp+2)!=':') && (i!=5)){
			printf("Expected Mac Address in format 01:02:03:04:05:06\n");
			return FALSE;
		}
		
		mn->PublicMac[i]=strtoul(Buff, NULL, 16);

		sp+=3;
	}

#ifdef DEBUG
	printf("Public MAC is %02X:%02X:%02X:%02X:%02X:%02X\n",
		mn->PublicMac[0],
		mn->PublicMac[1],
		mn->PublicMac[2],
		mn->PublicMac[3],
		mn->PublicMac[4],
		mn->PublicMac[5]);
#endif

	/*Now chain this on the end*/
	if (!MangleNodes){
		MangleNodes=mn;
	}else{
		t=MangleNodes;
		while (t->Next) MangleNodes=MangleNodes->Next;
		t->Next=mn;
	}

	return TRUE;
}

/**********************************************
* Set up mangling mac addresses on interfaces
* Needed for honeypots that use the same IP
**********************************************/
int InitMangleHardMac(){
	int	MangleID;
	
#ifdef DEBUGPATH
	printf("In InitMangleHardMac\n");
#endif

	MangleNodes=NULL;
	
	if ( (MangleID=CreateMangler("HardMac"))==MANGLE_NONE){
		printf("Couldn't create mangler HardMac\n");
		return FALSE;
	}
	
	Globals.Mangles[MangleID].MangleFunc=MangleHardMac;
	Globals.Mangles[MangleID].AddNode=MangleHardMacAddNode;
	
	if ( (EthernetDecoderID=GetDecoderByName("Ethernet"))==DECODER_NONE){
		printf("Couldn't find Ethernet Decoder\n");
		return FALSE;
	}

	if ( (ARPDecoderID=GetDecoderByName("ARP"))==DECODER_NONE){
		printf("Couldn't find ARP Decoder\n");
		return FALSE;
	}

	return TRUE;
}

