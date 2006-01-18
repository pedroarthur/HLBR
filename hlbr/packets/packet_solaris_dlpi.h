#ifndef _HLBR_PACKET_SOLARIS_DLPI_H_
#define _HLBR_PACKET_SOLARIS_DLPI_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "packet.h"

int OpenInterfaceSolarisDLPI(int InterfaceID);
int ReadPacketSolarisDLPI(int InterfaceID);
int WritePacketSolarisDLPI(int InterfaceID, unsigned char* Packet, int PacketLen);
int LoopThreadSolarisDLPI(int InterfaceID);

#endif
