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
#include "decode_http.h"
#include "decode_dns.h"
#include "decode_arp.h"

extern GlobalVars	Globals;

//#define DEBUG

/**
 * Given a Decoder's name, return its ID.
 */
int GetDecoderByName(char* Name){
	int 	i;
	
	DEBUGPATH;

	for (i=0;i<Globals.NumDecoders;i++)
		if (strcasecmp(Name, Globals.Decoders[i].Name)==0) return i;

	return DECODER_NONE;
}

/**
 * Set up the initial decoder tree.
 */
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
	if (!InitDecoderHTTP()) return FALSE;
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

/**
 * Allocate a decoder.
 */
int CreateDecoder(char* Name)
{
	int DecoderID;
	
	DEBUGPATH;

	/* check to see if this name is already used */
	DecoderID = GetDecoderByName(Name);
	if (DecoderID != DECODER_NONE) {
		printf("Decoder %s already exists\n", Name);
		return DECODER_NONE;
	}

	if (Globals.NumDecoders == MAX_DECODER_DEPTH) {
		fprintf(stderr, "Out of room for decoders\n");
		return DECODER_NONE;
	}
	
	DecoderID = Globals.NumDecoders;
	Globals.NumDecoders++;
	
	bzero(&Globals.Decoders[DecoderID], sizeof(DecoderRec));
	Globals.Decoders[DecoderID].ID=DecoderID;
	snprintf(Globals.Decoders[DecoderID].Name, MAX_NAME_LEN, Name);
	
#ifdef DEBUG
	printf("Allocated Decoder \"%s\" at number %i\n",Name, DecoderID);
#endif	
	
	return DecoderID;
}

/**
 * Add a new test to a decoder.
 * Each test defined in the rules files is read in the appropriate struct
 * and then linked to the corresponding decoder struct.
 * @return TRUE if test was added succesfully, otherwise FALSE
 */
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

/**
 * Add (link) a decoder to another decoder.
 * Link a decoder to a previous created decoder, so it's called after it.
 * Example: the TCP decoder should be linked to the IP decoder
 * @return TRUE if decoder was added succesfully, otherwise FALSE
 */
int DecoderAddDecoder(int ParentDecoderID, int ChildDecoderID)
{
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

		if (!This->NextChild)
			break;

		This=This->NextChild;
	}
	
	This->NextChild=Child;

	return TRUE;
}

/**
 * Add a new module to a decoder.
 * Modules are linked to decoders, so they're called after the decoder
 * finishes its job.
 * @return TRUE if module was added succesfully, otherwise FALSE
 */
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


/**
 * Apply a decoder (and child decoders, rules, and modules) to a packet.
 * This is one of the main functions responsible for everything HLBR does;
 * the other is ProcessPacket().
 * Decode will travel down the decoder tree, starting at the given
 * decoder, and applying the child decoders, as well as tests and modules.
 * @return FALSE if an error occurs (but not if a child decoder fails)
 * @remarks Basically this is what Decode does:
 * @li Gets the function for the requested decoder (DecodeFunc) and applies it;
 * the data produced by this function will be accessible by a pointer in the
 * corresponding DecoderData structure (every packet have an array of
 * DecoderData structs so the decoders can put their data there).
 * @li If the decoder generated data: applies all tests linked to this decoder
 * (see BindTestToDecoder() ), and then run the linked modules (currently
 * not used in HLBR).
 * @li If the decoder did NOT generate data: mark all rules 
 * (packet_rec::RuleBits) that depend on this decoder as inactive (that means,
 * didn't match the packet), without testing them, and leaves
 * @li Then, test if all rules were already tested (RuleBits), and if so, 
 * leaves (there is no need to apply more decoders)
 * @li Traverse the list of child decoders, calling them with this same function
 * @remarks Note that the actions defined in the configuration aren't 
 * executed here. They're executed by ProcessPacket(), after calling Decode().
 */
int Decode(int DecoderID, int PacketSlot)
{
	TestRec*	test;
	ModuleRec*	module;
	DecoderRec*	child;
	PacketRec*	p;

	DEBUGPATH;

	// Don't go there if we don't need to
	if (!Globals.Decoders[DecoderID].Active) 
		return TRUE;

#ifdef DEBUG
	printf("Applying decoder %s\n",Globals.Decoders[DecoderID].Name);
#endif

	p = &Globals.Packets[PacketSlot];

	/* apply this decoder */
	p->DecoderInfo[DecoderID].Data = Globals.Decoders[DecoderID].DecodeFunc(PacketSlot);

	if (p->DecoderInfo[DecoderID].Data) {
		if (!p->DecoderInfo[DecoderID].Data) {
			printf("What the hell is going on?\n");
		}

		p->DecoderInfo[DecoderID].DecoderID = DecoderID; // now this is redundant...
		p->DecodersUsed[p->NumDecoderData++] = DecoderID;

		/* apply the tests */
		test = Globals.Decoders[DecoderID].Tests;

		while (test) {
			if (test->Active)
				if (test->TestFunc)
					test->TestFunc(PacketSlot, test->TestNodes);
			test = test->Next;
		}

		// apply the modules
		module = Globals.Decoders[DecoderID].Modules;
		while (module) {
			if (module->Active)
				if (module->ModuleFunc) 
					module->ModuleFunc(PacketSlot);
			module=module->Next;
		}
	} else {
		// mark all the rules that depend on this decoder as inactive
		NotAndBitFields(p->RuleBits, Globals.Decoders[DecoderID].DependencyMask, p->RuleBits, Globals.NumRules);
		return TRUE;
	}

	// check to see if there are any rules left
	if (!BitFieldIsEmpty(p->RuleBits, Globals.NumRules)) {
#ifdef DEBUG
		printf("There are rules left\n");
#endif		
	} else {
#ifdef DEBUG
		printf("All rules have been eliminated\n");
#endif
		return TRUE;
	}

	// apply the bound decoders
	child = Globals.Decoders[DecoderID].Children;
	while (child) {
		if (!Decode(child->ID, PacketSlot)) {
			fprintf(stderr, "Decoder %s failed\n", child->Name);
		}
		child = child->NextChild;
	}

	return TRUE;
}


/**
 * Add a dependency to the decoder.
 * If a decoder fails, all the dependencies fail also. 
 * Used for fast pruning
 */
int DecoderSetDependency(int DecoderID, int TestID){

	DEBUGPATH;

	if (TestID > Globals.NumRules) return FALSE;

	SetBit(Globals.Decoders[DecoderID].DependencyMask, Globals.NumRules, TestID, 1);
	return TRUE;
}

/**
 * Get a particular decoder's data record.
 * Before the data records were added sequentially, now we're putting the data record
 * of a decoder right at that decoder's id index.
 */
inline int GetDataByID(int PacketSlot, int DecoderID, void** data){
	PacketRec*	p;

	DEBUGPATH;

	p = &Globals.Packets[PacketSlot];

	/*
	if (!p->DecoderInfo[DecoderID].Data){
		printf("Decoder Data %i was NULL\n", DecoderID);
		*data = NULL;
		return FALSE;
	} else {
	*/
		*data = p->DecoderInfo[DecoderID].Data;
		return TRUE;
	/*
	}
	*/
}
