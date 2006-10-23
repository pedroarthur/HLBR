#ifndef HLBR_SESSION_H
#define HLBR_SESSION_H

#include "../config.h"
#include "hlbr.h"

#define IP_START	1
#define IP_GROW		1
#define PORT_START	5
#define PORT_GROW	10

/* Timeout for a (TCP) session */
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

#define TCP_CACHE_SIZE		4*1460
#define TCP_QUEUE_SIZE		16	// max number of TCP packets to 'queue'


#ifdef TCP_STREAM
struct tcp_stream_piece {
	unsigned int		piece_start;	// seq number
	unsigned int		piece_end;
	int			PacketSlot;
};
/**
 * TCP stream buffer
 * Buffer to hold the last packets received in a TCP session, to make it 
 * possible to detect signatures across different packets.
 */
struct tcp_stream_buffer {
	unsigned char		num_pieces;
	struct tcp_stream_piece	pieces[TCP_QUEUE_SIZE];
	unsigned char		buffer[TCP_CACHE_SIZE];
	unsigned char		queue_size;
	int			queue[TCP_QUEUE_SIZE];	// packets waiting to enter TCPWindow
	/* TopSeq holds the sequence number of the first byte in the window, while
	   LastSeq holds the seq. number of the highest byte stored in the window. */
	unsigned int		TopSeq;
	unsigned int		LastSeq;
	unsigned char		RuleBits[MAX_RULES/8];
};
#endif

/**
 * Struct that represents the actual session.
 * Holds the source/dest ports, a pointer to the ip_pair struct, and other
 * info about the session (packet counts, connection state etc.)
 * @see ip_pair
 */
typedef struct port_pair{
	unsigned int		SessionID;
	unsigned short		Port1;
	unsigned short		Port2;
	struct ip_pair*		Parent;
	
	long int		FirstTime;
	long int		LastTime;
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

	/* Points to the other corresponding port_pair structure (one is srv->clnt,
	   the other is clnt->srv) */
	struct port_pair*	TheOtherPortPair;
#ifdef TCP_STREAM
	struct tcp_stream_buffer	Seqs;
#endif
} PP;

/**
 * Struct that represents the two IPs in a session.(?)
 * The two IPs are supposed to be server/client IPs. This struct doesn't hold
 * info about the actual session, only about the source/destination. 
 * Info about the session lies in the struct port_pair. 
 * @see port_pair
 */
typedef struct ip_pair{
	unsigned int	IP1;
	unsigned int	IP2;
	unsigned int	NumAllocated;
	unsigned int	NumPorts;
	PP**		Ports;
	struct ip_bin*	Parent;

	unsigned char	RefuseFromThisIP : 1;	/** < Refuse any sessions from IP1 in the future */
} IPP;

typedef struct ip_bin{
	unsigned int	NumAllocated;
	unsigned int	NumIPs;
	IPP**		Pairs;
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
