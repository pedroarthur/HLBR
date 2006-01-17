#ifndef HOGWASH_MODULE_H
#define HOGWASH_MODULE_H

#include "../config.h"
#include "../engine/hogwash.h"

#define MODULE_NONE	-1

int InitModules();
int CreateModule(char* Name);
int	GetModuleByName(char* Name);
int BindModuleToDecoder(int ModuleID, char* Decoder);
int ModuleParseArg(int ModuleID, char* Arg);

#endif
