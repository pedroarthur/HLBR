#ifndef HLBR_MESSAGE_H
#define HLBR_MESSAGE_H

#include "../config.h"
#include "hlbr.h"

#define	MESSAGE_ITEM_CHAR			1
#define	MESSAGE_ITEM_SIP			2
#define	MESSAGE_ITEM_DIP			3
#define	MESSAGE_ITEM_SPORT			4
#define	MESSAGE_ITEM_DPORT			5
#define MESSAGE_ITEM_YEAR			6
#define MESSAGE_ITEM_MONTH			7
#define MESSAGE_ITEM_DAY			8
#define MESSAGE_ITEM_MIN			9
#define MESSAGE_ITEM_SEC			10
#define MESSAGE_ITEM_USEC			11
#define MESSAGE_ITEM_HOUR			12
#define MESSAGE_ITEM_PACKET_NUM		13
#define MESSAGE_ITEM_ALERT_COUNT	14

MessageItem* ParseMessageString(char* MString);
void FreeMessage(MessageItem* MItem);
int ApplyMessage(MessageItem* MItem, int PacketSlot, char* Buff, int BuffLen);

#endif
