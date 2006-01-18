#ifndef _HLBR_PACKET_LINUX_RAW_H_
#define _HLBR_PACKET_LINUX_RAW_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "packet.h"

int OpenInterfaceLinuxRaw(int InterfaceID);
int ReadPacketLinuxRaw(int InterfaceID);
int WritePacketLinuxRaw(int InterfaceID, unsigned char* Packet, int PacketLen);
int LoopThreadLinuxRaw(int InterfaceID);

#endif
