#ifndef _HOGWASH_DECODE_H_
#define _HOGWASH_DECODE_H_

#include "../config.h"
#include "../engine/hogwash.h"

#define DECODER_NONE	-1

int InitDecoders();
int GetDecoderByName(char* Name);
int CreateDecoder(char* Name);
int DecoderAddTest(int DecoderID, int TestID);
int DecoderAddDecoder(int ParentDecoderID, int ChildDecoderID);
int DecoderAddModule(int DecoderID, int ModuleID);
int Decode(int DecoderID, int PacketSlot);
int DecoderSetDependency(int DecoderID, int TestID);
int GetDataByID(int PacketSlot, int DecoderID, void** data);

#endif
