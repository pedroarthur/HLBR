#ifndef _HLBR_PACKET_H_
#define _HLBR_PACKET_H_

#include "../config.h"
#include "../engine/hlbr.h"

#define MAX_IDLE_PACKETS		150

/**********************************
* These define each possible 
* packet type and proto
**********************************/
#define PACKET_TYPE_NONE		0
#define PACKET_TYPE_LINUX_RAW		1
#define PACKET_TYPE_PCAP		2
#define PACKET_TYPE_OBSD_BPF		3
#define PACKET_TYPE_OSX_BPF		4
#define PACKET_TYPE_TCPDUMP		5
#define PACKET_TYPE_SOLARIS_DLPI	6

#define PACKET_PROTO_NONE		0
#define PACKET_PROTO_IP			1
#define PACKET_PROTO_ETHERNET		2

#define MAX_KEY_LEN			128

#define INTERFACE_NONE			-1
#define INTERFACE_BROADCAST		99

#define PACKET_STATUS_IDLE		0
#define PACKET_STATUS_PENDING		1
#define PACKET_STATUS_SAVED		2
#define PACKET_STATUS_ALLOCATED		3
#define PACKET_STATUS_PROCESSING	4
#define PACKET_STATUS_WAITING		5
#define PACKET_STATUS_PERFORMING	6
#define PACKET_STATUS_SCHEDULING	7
#define PACKET_STATUS_SENDING		8

#define PACKET_ROLE_NORMAL		0
#define PACKET_ROLE_EXTERNAL		1
#define PACKET_ROLE_INTERNAL		2
#define PACKET_ROLE_HONEY		3

#define PACKET_NONE			-1

int GetPacketTypeByName(char* Name);
int GetPacketProtoByName(char* Name);
int GetPacketRoleByName(char* Name);

int GetInterfaceByName(char* Name);
int OpenInterfaces();
int OpenInterface(int InterfaceID);
int StartInterfaceThread(int InterfaceID);

int ReadPacket(int InterfaceID);
int WritePacket(int PacketSlot);

int GetEmptyPacket();
int AddPacketToPending(int PacketSlot);
int PopFromPending();
int AddPacketToWaiting (int PacketSlot);
int PopFromWaiting ();
int SchedulePacket (int PacketSlot);
int GetScheduledPacket (int InterfaceID);
void ReturnEmptyPacket(int PacketSlot);

int RuleIsActive(int PacketSlot, int RuleNum);
int SetRuleInactive(int PacketSlot, int RuleNum);

#endif
