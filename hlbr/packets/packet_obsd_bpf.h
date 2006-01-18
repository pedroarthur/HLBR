#ifndef _HLBR_PACKET_OBSD_BPF_H_
#define _HLBR_PACKET_OBSD_BPF_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "packet.h"

int OpenInterfaceOBSDBPF(int InterfaceID);
int ReadPacketOBSDBPF(int InterfaceID);
int WritePacketOBSDBPF(int InterfaceID, unsigned char* Packet, int PacketLen);
int LoopThreadOBSDBPF(int InterfaceID);

#endif
