#ifndef _HOGWASH_PACKET_TCPDUMP_H_
#define _HOGWASH_PACKET_TCPDUMP_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "packet.h"

int OpenInterfaceTCPDump(int InterfaceID);
int ReadPacketTCPDump(int InterfaceID);
int WritePacketTCPDump(int InterfaceID, unsigned char* Packet, int PacketLen);
int LoopThreadTCPDump(int InterfaceID);

#endif
