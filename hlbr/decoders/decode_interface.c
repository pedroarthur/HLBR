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
	
#ifdef DEBUGPATH
	printf("In DecodeInterface\n");
#endif

	p=&Globals.Packets[PacketSlot];

#ifdef DEBUG
	printf("Decoding the interface\n");
#endif
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

	return TRUE;
}
