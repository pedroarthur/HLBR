#ifndef HOGWASH_PACKET_CACHE_H
#define HOGWASH_PACKET_CACHE_H

#include "../config.h"
#include "../engine/hogwash.h"

#define MAX_QUERY_RESULTS	128
#define MAX_SAVES			1024
#define MAX_SAVES_PER_BIN	128

typedef struct save_rec{
	char				InUse;
	
	char*				Key;
	int					KeyLen;
	int					Timeout;
	int					PacketSlot;	
	int					PacketID;
	pthread_mutex_t		Mutex;
	int					LockID;
	
	int					NextTime;
	int					PrevTime;
} SaveRec;

typedef struct save_bin{
	unsigned char	NumInBin;
	int				Items[MAX_SAVES_PER_BIN];
}SaveBin;

typedef struct save_query{
	int			NumResults;
	int			Saves[MAX_QUERY_RESULTS];
	int			Packets[MAX_QUERY_RESULTS];
} SaveQuery;


int InitCache();
int SavePacket(int PacketSlot, char* Key, int KeyLen, int timeout);
SaveQuery* GetAndLockSavedPackets(char* Key, int KeyLen);
void UnlockSavedQuery(SaveQuery* q);
void FreeSaveQuery(SaveQuery* q);


#endif
