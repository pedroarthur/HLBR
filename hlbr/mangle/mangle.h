#ifndef HOGWASH_MANGE_H
#define HOGWASH_MANGE_H

#include "../config.h"
#include "../engine/hogwash.h"

#define MANGLE_NONE	-1

int InitManglers();
int CreateMangler(char* Name);
int GetManglerByName(char* Name);
int ManglerAdd(int MangleID, char* Args);
int Mangle(int PacketSlot, int SourceInterface, int TargetInterface);

#endif
