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

#ifdef TCP_STREAM_REASSEMBLY

#define TCP_PAYLOAD_BUFFER_SIZE	4*1460
#define TCP_QUEUE_SIZE		16	// max number of TCP packets to 'queue'
#define TCP_PAYLOAD_PIECES_SIZE	1024	// max number of TCP packets to put in the Queue (if it can hold them all)

struct tcp_stream_piece {
	unsigned int	piece_start;	// seq number
	unsigned int	piece_end;
	int		PacketSlot;
};

/**
 * TCP stream.
 * This struct represents a TCP stream; the concept is that in a TCP session
 * there are two streams, from the client to the server and from the server to
 * the client.
 * There are a buffer to hold the last packets received in a TCP session, 
 * to make it possible to detect signatures across different packets.
 * Details:
 * - Pieces[] holds the references to each packet stored in Payloads (the
 * PacketSlot number and the start/end sequence numbers). Note that the packets
 * may not be ordered by their sequence numbers here!
 * - Payloads is a mere buffer for copying the packets' payloads all together.
 * Note: only sequential payloads are stored here; packets that arrive out of
 * order are put in the Queue[].
 * - Queue[] holds the packets (the PacketSlots) that arrived out of sequence,
 * until they can be mounted in Payloads and put in Pieces[].
 * -TopSeq holds the sequence number of the first byte in Payloads - the seq
 * number of the 'oldest' packet in Pieces[]
 * - LastSeq holds the sequence number of the highest byte stored in Payloads.
 */
struct tcp_stream {
	unsigned short int	NumPieces;
	unsigned int		TotalPackets;	/**< keeps track of how many packets this stream has buffered (in correct order, not counting the ones in queue) until now */
	struct tcp_stream_piece	Pieces[TCP_QUEUE_SIZE];
	unsigned char		Payloads[TCP_PAYLOAD_BUFFER_SIZE];
	unsigned char		QueueSize;
	int					Queue[TCP_PAYLOAD_PIECES_SIZE];
	unsigned int		TopSeq;
	unsigned int		LastSeq;
};

#endif // TCP_STREAM_REASSEMBLY

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

#ifdef TCP_STREAM_REASSEMBLY
	/* The two streams in a TCP session (cli->srv and srv->cli) */
	struct tcp_stream*	Stream0;
	struct tcp_stream*	Stream1;
	char			noreassemble;
#endif
} PP;

/**
 * Struct that represents the two IPs in a session (?).
 * The two IPs are supposed to be server/client IPs. This struct doesn't hold
 * info about the actual session, only about the source/destination IPs.
 * Info about the session lies in the struct port_pair. 
 * @see port_pair
 * @see FindIPPair()
 */
typedef struct ip_pair {
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
#ifdef TCP_STREAM_REASSEMBLY
int AssignSessionTCP(int, void*);
#endif

#endif // HLBR_SESSION_H
