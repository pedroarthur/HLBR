#include "decode_interface.h"
#include <stdio.h>
#include <stdlib.h>

//#define DEBUG

extern GlobalVars	Globals;

/***************************************
* Apply the interface decoding (none)
****************************************/
void* DecodeInterface(int PacketSlot){
	InterfaceData*	data;
	PacketRec*		p;
	
	DEBUGPATH;

	p=&Globals.Packets[PacketSlot];

	/*do the decoding*/

	data=(InterfaceData*)malloc(sizeof(InterfaceData));
	data->r=&Globals.Interfaces[p->InterfaceNum];

	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderInterface(){
	int DecoderID;

    DEBUGPATH;
	
	if ((DecoderID=CreateDecoder("Interface"))==DECODER_NONE){
		DBG( PRINTERROR("Couldn't Allocate Decoder Interface\n") );
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeInterface;
	Globals.Decoders[DecoderID].Free=free;

	return TRUE;
}
