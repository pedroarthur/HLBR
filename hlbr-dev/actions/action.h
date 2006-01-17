#ifndef _HOGWASH_ACTION_H_
#define _HOGWASH_ACTION_H_

#include "../config.h"
#include "../engine/hogwash.h"

#define ACTION_NONE	-1

int InitActions();
int	GetActionByName(char* Name);
int CreateAction(char* Name);
int BuildMessageString(char* Message, int PacketSlot, char* TargetBuff, int TargetBuffLen);
int PerformActions(int PacketSlot);
int	LogMessage(char* Message);

#endif
