#ifndef HLBR_SESSION_H
#define HLBR_SESSION_H

#include "../config.h"
#include "hlbr.h"

#define IP_START	1
#define IP_GROW		1
#define PORT_START	5
#define PORT_GROW	10

/* Timeout for a (TCP) session */
#define SESSION_FORCE_TIMEOUT		60

/* TCP session direction */
#define SESSION_UNKNOWN			0
#define SESSION_IP1_SERVER		1
#define SESSION_IP2_SERVER		2
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

/**
 * Struct that represents the actual (TCP) session.
 * Holds the source/dest ports, a pointer to the ip_pair struct, and other
 * info about the session (packet counts, connection state etc.)
 * @see ip_pair
 */
typedef struct port_pair {
	unsigned int		SessionID;
	unsigned short		Port1;
	unsigned short		Port2;
	struct ip_pair*		Parent;
	
	long int		FirstTime;
	long int		LastTime;
	unsigned char		Direction;
	unsigned char		Error;
	/* Notes: this (Error) is being used to flag:
	   - srv->cli:ServerAck doesn't match ClientSeq+1 during handshake1
	   - srv->cli:ServerAck/ClientSeq don't match stored ones in handshake2
	   - srv->cli:any unexpected packet order
	   - cli->srv:any unexpected packet order (both with no fin/rst and
	     with any of them)
	*/
	
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

	/** These two fields (TimeNext and TimePrev) are used to track
	 * port_pair structs that are in the "time list".
	 * @see AddToTime
	 * @see UpdateTime
	 * @see TimeoutSessions
	 */
	struct port_pair*	TimeNext;
	struct port_pair*	TimePrev;
} PP;

/**
 * Struct that represents the two IPs in a session (?).
 * The two IPs are supposed to be server/client IPs. This struct doesn't hold
 * info about the actual session, only about the source/destination IPs.
 * Info about the session lies in the struct port_pair. 
 * @see port_pair
 * @see FindIPPair()
 */
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
