#ifndef HOGWASH_SESSION_H
#define HOGWASH_SESSION_H

#include "../config.h"
#include "hogwash.h"

#define IP_START	1
#define IP_GROW		1
#define PORT_START	5
#define PORT_GROW	10

#define SESSION_FORCE_TIMEOUT	60

#define SESSION_UNKNOWN				0
#define SESSION_IP1_SERVER			1
#define SESSION_IP2_SERVER			2
#define SESSION_IP1_SERVER_MAYBE	3
#define SESSION_IP2_SERVER_MAYBE	4


#define TCP_STATE_NEW		0
#define TCP_STATE_SYN		1
#define TCP_STATE_SYNACK	2
#define TCP_STATE_DATA		3
#define TCP_STATE_FIN		4
#define TCP_STATE_RESET		6
#define TCP_STATE_LATE		7

struct ip_pair;
struct ip_bin;

typedef struct port_pair{
	unsigned int		SessionID;
	unsigned short		Port1;
	unsigned short		Port2;
	struct ip_pair*		Parent;
	
	long int			FirstTime;
	long int			LastTime;
	unsigned char		Direction;
	unsigned char		Error;
	
	unsigned short		TCPCount;
	unsigned short		UDPCount;
	unsigned short		ICMPCount;
	unsigned short		OtherCount;

	unsigned char		ServerState;
	unsigned int		ServerSeq;
	unsigned int		ServerAck;
	unsigned char		ServerFin;
	unsigned char		ClientState;
	unsigned int		ClientSeq;
	unsigned int		ClientAck;
	unsigned char		ClientFin;

	struct port_pair*	TimeNext;
	struct port_pair*	TimePrev;
} PP;

typedef struct ip_pair{
	unsigned int	IP1;
	unsigned int	IP2;
	unsigned int	NumAllocated;
	unsigned int	NumPorts;
	PP**			Ports;
	struct ip_bin*	Parent;
} IPP;

typedef struct ip_bin{
	unsigned int	NumAllocated;
	unsigned int	NumIPs;
	IPP**			Pairs;
} IPB;

typedef struct session_func{
	void (*Func) (PP* Port, void* Data);
	void*					Data;
	struct session_func*	Next;
} SFunc;

int InitSession();
int AddSessionCreateHandler(void (*Func) (PP* Port, void* Data), void* Data);
int AddSessionDestroyHandler(void (*Func) (PP* Port, void* Data), void* Data);

#endif
