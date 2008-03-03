#include "decode.h"
#include <stdio.h>
#include <string.h>
#include "../engine/bits.h"
#include "../packets/packet.h"
#ifdef _SOLARIS_
#include <strings.h>
#endif

/*************************************
* include for each decoder goes here
*************************************/
#include "decode_interface.h"
#include "decode_ethernet.h"
#include "decode_ip.h"
#include "decode_ip_defrag.h"
#include "decode_icmp.h"
#include "decode_udp.h"
#include "decode_tcp.h"
#include "decode_uri.h"
#include "decode_dns.h"
#include "decode_arp.h"

extern GlobalVars	Globals;

//#define DEBUG

/**************************************
* Give a Decoder's name, return it's ID
**************************************/
int GetDecoderByName(char* Name){
	int 	i;
	
	DEBUGPATH;

	for (i=0;i<Globals.NumDecoders;i++)
		if (strcasecmp(Name, Globals.Decoders[i].Name)==0) return i;

	return DECODER_NONE;
}

/*************************************
* Set up the initial decoder tree
*************************************/
int InitDecoders(){
	int	RootDecoder;

	DEBUGPATH;

	if (!InitDecoderInterface()) return FALSE;
	if (!InitDecoderEthernet()) return FALSE;
	if (!InitDecoderIP()) return FALSE;
	if (!InitDecoderIPDefrag()) return FALSE;
	if (!InitDecoderICMP()) return FALSE;
	if (!InitDecoderUDP()) return FALSE;
	if (!InitDecoderTCP()) return FALSE;
	if (!InitDecoderURI()) return FALSE;
	if (!InitDecoderDNS()) return FALSE;
	if (!InitDecoderARP()) return FALSE;

	/*set the interface decoder as the root decoder*/
	RootDecoder=GetDecoderByName("Interface");
	if (RootDecoder==DECODER_NONE){
		printf("Error Decoder Interface not found\n");
		return FALSE;
	}
	Globals.DecoderRoot=RootDecoder;
	
	/*for session tracking some decoders should always be active*/
	Globals.Decoders[GetDecoderByName("IP")].Active=TRUE;
	Globals.Decoders[GetDecoderByName("TCP")].Active=TRUE;
	Globals.Decoders[GetDecoderByName("UDP")].Active=TRUE;
	Globals.Decoders[GetDecoderByName("ICMP")].Active=TRUE;
	
		
	return TRUE;
}

/*************************************
* Allocate a decoder
**************************************/
int CreateDecoder(char* Name){
	int DecoderID;
	
	DEBUGPATH;

	/*check to see if this name is already used*/
	DecoderID=GetDecoderByName(Name);
	if (DecoderID!=DECODER_NONE){
		printf("Decoder %s already exists\n",Name);
		return DECODER_NONE;
	}
	
	DecoderID=Globals.NumDecoders;
	Globals.NumDecoders++;
	
	bzero(&Globals.Decoders[DecoderID], sizeof(DecoderRec));
	Globals.Decoders[DecoderID].ID=DecoderID;
	snprintf(Globals.Decoders[DecoderID].Name, MAX_NAME_LEN, Name);
	
#ifdef DEBUG
	printf("Allocated Decoder \"%s\" at number %i\n",Name, DecoderID);
#endif	
	
	return DecoderID;
}

/************************************************
* Add a new test to a decoder
************************************************/
int DecoderAddTest(int DecoderID, int TestID){
	TestRec*	Test;
	DecoderRec*	Decoder;
	TestRec*	This;

	DEBUGPATH;

	Test=&Globals.Tests[TestID];
	Decoder=&Globals.Decoders[DecoderID];
	
	if (!Decoder->Tests){
		Decoder->Tests=Test;
		return TRUE;
	}
	
	/*check to see if it's already bound*/
	This=Decoder->Tests;
	while (1){
		if (This->ID==Test->ID){
			printf("This Test already bound to this decoder\n");
			return FALSE;
		}
		if (!This->Next) break;
		This=This->Next;
	}
	
	This->Next=Test;
	
	Test->DecoderID=DecoderID;

	return TRUE;
}

/************************************************
* Add a decoder to another decoder
************************************************/
int DecoderAddDecoder(int ParentDecoderID, int ChildDecoderID){
	DecoderRec*	Child;
	DecoderRec*	Parent;
	DecoderRec*	This;

	DEBUGPATH;

	Parent=&Globals.Decoders[ParentDecoderID];
	Child=&Globals.Decoders[ChildDecoderID];
	Child->Parent=Parent;
		
	if (!Parent->Children){
		Parent->Children=Child;
		return TRUE;
	}
	
	/*check to see if it's already bound*/
	This=Parent->Children;
	while (1){
		if (This->ID==Child->ID){
			printf("This decoder already bound to this decoder\n");
			return FALSE;
		}
		if (!This->NextChild) break;
		This=This->NextChild;
	}
	
	This->NextChild=Child;

	return TRUE;

}

/************************************************
* Add a new module to a decoder
************************************************/
int DecoderAddModule(int DecoderID, int ModuleID){
	ModuleRec*	Module;
	DecoderRec*	Decoder;
	ModuleRec*	This;

	DEBUGPATH;

	Module=&Globals.Modules[ModuleID];
	Decoder=&Globals.Decoders[DecoderID];
	
	if (!Decoder->Modules){
		Decoder->Modules=Module;
		return TRUE;
	}
	
	/*check to see if it's already bound*/
	This=Decoder->Modules;
	while (1){
		if (This->ID==Module->ID){
			printf("This Module already bound to this decoder\n");
			return FALSE;
		}
		if (!This->Next) break;
		This=This->Next;
	}
	
	This->Next=Module;
	
	Module->DecoderID=DecoderID;

	return TRUE;
}


/*******************************************
* Apply a decoder to a packet
*******************************************/
int Decode(int DecoderID, int PacketSlot){
	TestRec*	test;
	ModuleRec*	module;
	DecoderRec*	child;
	PacketRec*	p;

	DEBUGPATH;

	/*Don't go there if we don't need to*/
	if (!Globals.Decoders[DecoderID].Active) return TRUE;


#ifdef DEBUG
	printf("Applying decoder %s\n",Globals.Decoders[DecoderID].Name);
#endif

	p=&Globals.Packets[PacketSlot];

	if (p->NumDecoderData==MAX_DECODER_DEPTH){
		printf("Out of room for decoders\n");
		return FALSE;
	}

	/*apply this decoder*/
	p->DecoderInfo[p->NumDecoderData].Data=Globals.Decoders[DecoderID].DecodeFunc(PacketSlot);
	if (p->DecoderInfo[p->NumDecoderData].Data){
		if (!p->DecoderInfo[p->NumDecoderData].Data){
			printf("What the hell is going on?\n");
		}
		p->DecoderInfo[p->NumDecoderData].DecoderID=DecoderID;
		p->NumDecoderData++;

		/*apply the tests*/
		test=Globals.Decoders[DecoderID].Tests;
		while (test){
			if (test->Active)
			if (test->TestFunc) test->TestFunc(PacketSlot, test->TestNodes);
			test=test->Next;
		}

		/*apply the modules*/
		module=Globals.Decoders[DecoderID].Modules;
		while (module){
			if (module->Active)
			if (module->ModuleFunc) module->ModuleFunc(PacketSlot);
			module=module->Next;
		}
	}else{
		/*mark all the rules that depend on this decoder as inactive*/
		NotAndBitFields(p->RuleBits, Globals.Decoders[DecoderID].DependencyMask, p->RuleBits, Globals.NumRules);
		return TRUE;
	}		

	/*check to see if there are any rules left*/
	if (!BitFieldIsEmpty(p->RuleBits, Globals.NumRules)){
#ifdef DEBUG	
		printf("There are rules left\n");
#endif		
	}else{
#ifdef DEBUG
		printf("All rules have been eliminated\n");
#endif				
		return TRUE;
	}

	/*apply the bound decoders*/
	child=Globals.Decoders[DecoderID].Children;
	while (child){
		if (!Decode(child->ID, PacketSlot)){
			printf("Decoder %s failed\n",child->Name);
		}
		child = child->NextChild;
	}


	return TRUE;
}

/****************************************************
* Add a dependency to the decoder
* If a decoder fails, all the dependencies fail also
* Used for fast pruning
****************************************************/
int DecoderSetDependency(int DecoderID, int TestID){

	DEBUGPATH;

	if (TestID > Globals.NumRules) return FALSE;

	SetBit(Globals.Decoders[DecoderID].DependencyMask, Globals.NumRules, TestID, 1);
	return TRUE;
}

/******************************************
* Get a particular decoder's data record
*******************************************/
int GetDataByID(int PacketSlot, int DecoderID, void** data){
	int 		i;
	PacketRec*	p;

	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	for (i=p->NumDecoderData-1;i>=0;i--){
		if (p->DecoderInfo[i].DecoderID==DecoderID){
			if (!p->DecoderInfo[i].Data){
				printf("Decoder Data %i was NULL\n", DecoderID);
				*data=NULL;
				return FALSE;
			}else{
				*data=p->DecoderInfo[i].Data;
				return TRUE;
			}
		}
	}

#ifdef DEBUG
	printf("Decoder Data %i not found\n",DecoderID);
#endif
	
	return FALSE;
}
