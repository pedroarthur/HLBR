#ifndef _HLBR_H_
#define _HLBR_H_

#include "../config.h"
#include <sys/time.h>
#ifdef HAS_THREADS
#include <pthread.h>
#endif

#define DEBUGLOCKS

#include "num_list.h"
#include "session.h"

#define MAJOR_VERSION	1
#define MINOR_VERSION	1

#define MAX_PACKET_SIZE			65536+14+1
#define TYPICAL_PACKET_SIZE		16000
#define MAX_NAME_LEN			20
#define MAX_RULES			10240
#define MAX_INTERFACES			8
#define MAX_DECODERS			128
#define MAX_TESTS			1024
#ifdef _OBSD_
#define IDLE_TIMEOUT			100000
#else
#define IDLE_TIMEOUT			200		/*usec's*/
#endif
#define MAX_DECODER_DEPTH		16
#define MAX_MESSAGE_LEN			256
#define MAX_ACTIONS			16
#define MAX_ACTION_ITEMS		64
#define MAX_ITEMS_PER_ACTION	16
#define MAX_ROUTES				16
#define MAX_MANGLERS			8
#define MAX_MODULES				16
#define MAX_LISTS				16
#define MAX_TIMERS				16
#define MAX_PACKETS				512

#define DEFAULT_SENSOR_NAME	"Default Sensor"
#define DEFAULT_SENSOR_ID	0

#define MAX_INTERFACE_NAME_LEN	256

#define LIST_TYPE_IP		1
#define LIST_TYPE_NUM		2
#define LIST_TYPE_PORT		3
#define LIST_TYPE_IPPORT	4

#define USER_RULE_START		50000

/*Holds the data from all the decoders already applied*/
typedef struct decoder_data{
	int						DecoderID;
	void*					Data;
} DecoderData;

typedef struct packet_rec{
	int			PacketSlot; /*position in the packet array*/
	unsigned int		PacketNum;  /*used to track the packet through the system*/
	
	int			InterfaceNum;
	int			TargetInterface;
	
	unsigned char*		RawPacket;
	char			Pad[2];  /*to make word aligment work out on Solaris*/
	unsigned char		TypicalPacket[TYPICAL_PACKET_SIZE];
	char			LargePacket;
	int			PacketLen;
	
	unsigned char		RuleBits[MAX_RULES/8];
	struct timeval		tv;
	
	DecoderData		DecoderInfo[MAX_DECODER_DEPTH];
	int			NumDecoderData;
	int			BeginData;	/*first byte not decoded yet*/
	
	char			PassRawPacket; /*true if we pass this one as is*/	
	int			SaveCount;
	char			Status;     /*where the packet is in the processing loop*/
	
	pthread_mutex_t		Mutex;
	int			LockID;	
	
	struct port_pair*	Stream;
} PacketRec;

typedef struct interface_rec{
	char		Name[MAX_INTERFACE_NAME_LEN];
	int			ID;
	int			Type;	/*defined in packet.h*/
	int			Proto;
	int			MTU;
	int			FD;
	char		IsPollable;
	char		Role;
	pthread_t	Thread;
	int			ThreadID;
	void*		User;
} InterfaceRec;

typedef struct test_node{
	int			RuleID;
	void*			Data;
	struct test_node*	Next;
} TestNode;

typedef struct test_rec{
	char				Name[MAX_NAME_LEN];
	char				ShortName[MAX_NAME_LEN];
	int					ID;
	int					DecoderID;
	char				Active; /*true if anything actually uses it*/
	TestNode*			TestNodes;
	struct test_rec*	Next;   /*next test for the decoder*/
	unsigned char		DependencyMask[MAX_RULES/8];
	
	int (*AddNode)(int TestID, int RuleID, char* Args);
	int (*FinishedSetup)();
	int (*TestFunc)(int PacketSlot, TestNode* Nodes);
} TestRec;

typedef struct module_rec{
	char				Name[MAX_NAME_LEN];
	int					ID;
	int					DecoderID;
	char				Active;	/*true if anything actually uses it*/
	
	struct module_rec* Next;	
	
	int (*ParseArg) (char* Arg);
	void (*ModuleFunc) (int PacketSlot);
} ModuleRec;


typedef struct decoder_rec{
	char				Name[MAX_NAME_LEN];
	int					ID;
	unsigned char		DependencyMask[MAX_RULES/8];		
	struct test_rec*	Tests;
	struct module_rec*	Modules;
	struct decoder_rec*	Children;
	struct decoder_rec*	Parent;	
	struct decoder_rec*	NextChild;
	
	void* (*DecodeFunc) (int PacketSlot);
	
	char				Active;	/*true if anything actually uses it*/
} DecoderRec;

typedef struct action_item{
	char				Name[MAX_NAME_LEN];
	int					ID;
	
	int 	(*ActionFunc)(int RuleNum, int PacketSlot, void* Data);
	int		(*MessageFunc)(char* Message, void* Data);
	void* 	(*ParseArgs)(char* Args);
} ActionItem;

typedef struct action_rec{
	char				Name[MAX_NAME_LEN];
	int					ID;
	
	int					ActionItems[MAX_ITEMS_PER_ACTION];
	void*				ActionItemData[MAX_ITEMS_PER_ACTION];
	int					NumItems;
} ActionRec;

typedef struct message_item{
	int						Type;
	int						Value;
	struct message_item*	Next;
} MessageItem;

typedef struct rule_rec{
	int					ID;
	MessageItem*		MessageFormat;
	int					GlobalID;
	int					Revision;
	int					ModifyDate;
	int					Action;
} RuleRec;

typedef struct route_rec{
	int					ID;
	char				Name[MAX_NAME_LEN];	
	char				Active;
	
	int (*RouteFunc)(int PacketSlot);
	int (*AddNode)(int RouteID, char* Args);
} RouteRec;

typedef struct mangle_rec{
	int					ID;
	char				Name[MAX_NAME_LEN];
	char				Active;
	
	int (*MangleFunc)(int PacketSlot, int SourceInterface, int DestInterface);
	int (*AddNode)(int MangleID, char* Args);
} MangleRec;

typedef struct global_list{
	NumList*	List;
	char		Name[MAX_NAME_LEN];
	int			Type;
} GlobalList;

typedef struct func_list{
	int					(*Func) (void* Data);
	void*				Data;
	struct func_list*	Next;
} FuncList;

typedef struct timer_rec{
	char			InUse;
	char			Name[MAX_NAME_LEN];
	unsigned int	Interval;
	int				LastTime;
	void*			User;
	/*return TRUE to repeat the timer*/
	int (*TimerFunc) (int TimerID, int Time, void* User);
} TimerRec;


typedef struct global_vars{
	char*			SensorName;
	int				SensorID;

	char			Done;
	char			UseThreads;	
	char			ParseOnly;
	char*			ConfigFilename;
	char*			RulesFilename;	
	char*			LogDir;
	int				PacketLimit;
	MessageItem*	AlertHeader;
	unsigned int	AlertCount;
	
	PacketRec		Packets[MAX_PACKETS];
	int				IdleCount;
	int				PendingCount;
	int				SavedCount;
	int				AllocatedCount;
	int				ProcessingCount;
	
	RuleRec			Rules[MAX_RULES];
	int				NumRules;
	
	InterfaceRec	Interfaces[MAX_INTERFACES];
	int				NumInterfaces;
	
	DecoderRec		Decoders[MAX_DECODERS];
	int				NumDecoders;
	int				DecoderRoot;
	
	ModuleRec		Modules[MAX_MODULES];
	int				NumModules;
	
	TestRec			Tests[MAX_TESTS];
	int				NumTests;	
	
	ActionItem		ActionItems[MAX_ACTION_ITEMS];
	int				NumActionItems;
	
	ActionRec		Actions[MAX_ACTIONS];
	int				NumActions;
	
	RouteRec		Routes[MAX_ACTIONS];
	int				NumRoutes;

	MangleRec		Mangles[MAX_ACTIONS];
	int				NumMangles;
	
	GlobalList		Lists[MAX_LISTS];
	int				NumLists;

	TimerRec		Timers[MAX_TIMERS];

	FuncList*		ShutdownFuncs;	
	
	/*statistical counts*/
	int				PacketsPerSec;
	int				TCPPerSec;
	int				UDPPerSec;

	/* logging flags */
	unsigned char			logSession;
	unsigned char			logSession_BeginEnd;
} GlobalVars;


#define GET_SESSION_1		1001
#define GET_SESSION_2		1002 
#define GET_SESSION_3		1003
#define ADD_PACKET_1		2001
#define POP_PACKET_1		3001
#define GET_PACKET_1		4001
#define RETURN_PACKET_1		5001
#define FREE_SAVED_1		6001
#define TIMEOUT_SAVED_1		7001
#define TIMEOUT_SAVED_2		7002
#define SAVE_PACKET_1		8001
#define SAVE_PACKET_2		8002
#define GET_SAVED_1			9001
#define GET_SAVED_2			9002
#define GET_SAVED_3			9003
#define UNLOCK_SAVED_1		10001
#define FRAG_LOCK_1			11001

int hlbr_mutex_lock(pthread_mutex_t*	mutex, int ID, int* LockID);
int hlbr_mutex_trylock(pthread_mutex_t* mutex, int ID, int* LockID);
int hlbr_mutex_unlock(pthread_mutex_t* mutex);

/*put this somewhere else later*/
#define LIST_NONE	-1
int GetListByName(char* Name);
int AddShutdownHandler(int (*func)(void* data), void* data);

#define TIMER_NONE	-1
int CreateTimer(char* Name, unsigned int Interval, int (*TimerFunc)(int TimerID, int Time, void* user), void* User);

#endif
