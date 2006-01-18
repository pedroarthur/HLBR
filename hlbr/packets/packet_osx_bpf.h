#ifndef _HLBR_PACKET_OSX_BPF_H_
#define _HLBR_PACKET_OSX_BPF_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "packet.h"

int OpenInterfaceOSXBPF(int InterfaceID);
int ReadPacketOSXBPF(int InterfaceID);
int WritePacketOSXBPF(int InterfaceID, unsigned char* Packet, int PacketLen);
int LoopThreadOSXBPF(int InterfaceID);

#endif
