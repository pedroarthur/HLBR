#ifndef _HLBR_ACTION_H_
#define _HLBR_ACTION_H_

#include "../config.h"
#include "../engine/hlbr.h"

#define ACTION_NONE	-1

int InitActions();
int	GetActionByName(char* Name);
int CreateAction(char* Name);
int BuildMessageString(char* Message, int PacketSlot, char* TargetBuff, int TargetBuffLen);
int PerformActions(int PacketSlot);
int	LogMessageAllActions(char* Message);

#endif
