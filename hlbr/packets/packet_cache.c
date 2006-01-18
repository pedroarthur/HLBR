#include "packet_cache.h"
#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

pthread_mutex_t		SavedMutex;
int					SaveLockID;
SaveRec				Saves[MAX_SAVES];
SaveBin				SBins[65536];

int					SaveTimeHead;
int					SaveTimeTail;

//#define DEBUG
#define DEBUGLOCKS

extern GlobalVars	Globals;

/*********************************
* Get ready for some caching
*********************************/
int InitCache(){
#ifdef DEBUGPATH
	printf("In InitCache\n");
#endif

	bzero(Saves, sizeof(SaveRec)*MAX_SAVES);
	bzero(SBins, sizeof(SaveBin)*65536);
	
	return TRUE;
}


/***********************************************
* Calculate the hash of this key
***********************************************/
unsigned short HashKey(char* Key, int KeyLen){
	unsigned short 	KeyHash;
	int				i;
	
#ifdef DEBUGPATH
	printf("In HashKey\n");
#endif	

	if (!Key){
		printf("Internal Error: Key was Null in HashKey\n");
		return 0;
	}

	KeyHash=0;
	for (i=0;i<KeyLen/2;i++){
		KeyHash=KeyHash^((unsigned short*)Key)[i];
	}
	if (KeyLen%2) KeyHash=KeyHash+Key[KeyLen-1];
	
	return KeyHash;
}

/**********************************************************
* We no longer need this one
* Assumes the caller locks and unlocks everything
**********************************************************/
void FreeSaved(int SaveID){
	unsigned short 	KeyHash;
	SaveRec*		s;
	int				i,j;
	
#ifdef DEBUGPATH
	printf("in FreeSaved\n");
#endif

#ifdef DEBUG
	printf("Removing a packet\n");
#endif

	s=&Saves[SaveID];

	/*Take it off the time chain*/
	if (SaveTimeHead==SaveID) SaveTimeHead=Saves[SaveID].NextTime;
	if (SaveTimeTail==SaveID) SaveTimeTail=Saves[SaveID].PrevTime;
	
	if (s->PrevTime != -1){
		Saves[s->PrevTime].NextTime=s->NextTime;
	}
	if (s->NextTime != -1){
		Saves[s->NextTime].PrevTime=s->PrevTime;
	}

	/*take it out of the bin*/
	KeyHash=HashKey(s->Key,s->KeyLen);
	for (i=0;i<SBins[KeyHash].NumInBin;i++){
		if (SBins[KeyHash].Items[i]==SaveID){
			for (j=i;j<SBins[KeyHash].NumInBin-1;j++){
				SBins[KeyHash].Items[j]=SBins[KeyHash].Items[j+1];
				SBins[KeyHash].NumInBin--;
			}
		}
	}
	
	/*Mark it as free*/
	Saves[SaveID].InUse=FALSE;
	free(Saves[SaveID].Key);
	Saves[SaveID].Key=NULL;
	Saves[SaveID].KeyLen=0;
	Saves[SaveID].NextTime=-1;
	Saves[SaveID].PrevTime=-1;
	hlbr_mutex_unlock(&Globals.Packets[Saves[SaveID].PacketSlot].Mutex);
	hlbr_mutex_unlock(&Saves[SaveID].Mutex);
	
	/*return the packet into distribution*/
	Globals.Packets[Saves[SaveID].PacketSlot].SaveCount--;
	ReturnEmptyPacket(Saves[SaveID].PacketSlot);

	/*unlock the saved structs*/
	Globals.SavedCount--;
}

/**********************************************************
* We no longer need these packets
***********************************************************/
void FreeSaveQuery(SaveQuery* q){
	int		i;
#ifdef DEBUGPATH
	printf("In FreeSaveQuery\n");
#endif

	if (!q) return;

	/*lock the saved structs*/
	hlbr_mutex_lock(&SavedMutex, FREE_SAVED_1, &SaveLockID);
	
	for (i=0;i<q->NumResults;i++){
		FreeSaved(q->Saves[i]);
	}
	
	free(q);
	
	/*unlock the saved structs*/
	hlbr_mutex_unlock(&SavedMutex);
}

/********************************************
* timeout anybody that needs it
* Assumes the caller locks everything
*********************************************/
void TimeoutSavedPackets(long CurTime){
	int			This;
	int			DelPacket;

#ifdef DEBUGPATH
	printf("In TimeoutSavedPackets\n");
#endif

	/*check to see if there is anything to time out*/
	if (Globals.SavedCount==0) return;

	DelPacket=-1;
	This=SaveTimeHead;
	while (This!=-1){
		hlbr_mutex_lock(&Saves[This].Mutex, TIMEOUT_SAVED_1, &Saves[This].LockID);
		if (CurTime > Saves[This].Timeout){
			FreeSaved(This);
			hlbr_mutex_unlock(&Saves[This].Mutex);
			This=SaveTimeHead;
		}else{
#ifdef DEBUG		
			printf("Didn't need to be timed out\n");
#endif						
			hlbr_mutex_unlock(&Saves[This].Mutex);
			return;
		}
	}
}

/********************************************
* Go and find a free saved record
*
* This is the absolutely slowest way to do 
* this.
********************************************/
int GetFreeSaved(){
	int		i;
#ifdef DEBUGPATH
	printf("in GetFreeSaved\n");
#endif
	for (i=0;i<MAX_SAVES;i++){
		if (!Saves[i].InUse) return i;
	}
	
	return -1;
}

/********************************************
* Save a packet for later
*********************************************/
int SavePacket(int PacketSlot, char* Key, int KeyLen, int Timeout){
	unsigned short	KeyHash;
	int				SaveID;
	
#ifdef DEBUGPATH
	printf("In SavePacket\n");
#endif

	hlbr_mutex_lock(&SavedMutex, SAVE_PACKET_1, &SaveLockID);
	TimeoutSavedPackets(Globals.Packets[PacketSlot].tv.tv_sec);	
	hlbr_mutex_lock(&Globals.Packets[PacketSlot].Mutex, SAVE_PACKET_2, &Globals.Packets[PacketSlot].LockID);

	/*Create a record to hold the new packet*/
	if ( (SaveID=GetFreeSaved())==-1){
		printf("There are no free save records\n");
		hlbr_mutex_unlock(&SavedMutex);
		return FALSE;
	}

	Saves[SaveID].InUse=TRUE;	
	Saves[SaveID].Key=malloc(KeyLen+1);
	memcpy(Saves[SaveID].Key, Key, KeyLen);
	Saves[SaveID].KeyLen=KeyLen;
	Saves[SaveID].PacketSlot=PacketSlot;
	Saves[SaveID].Timeout=Globals.Packets[PacketSlot].tv.tv_sec+Timeout;

	/*push the packet onto the time list*/
	if (SaveTimeHead==-1){
#ifdef DEBUG
		printf("First Packet into the cache\n");
#endif		
		SaveTimeHead=SaveID;
		SaveTimeTail=SaveID;
	}else{
		Saves[SaveTimeTail].NextTime=SaveID;
		SaveTimeTail=SaveID;
	}
	
	/*put the SaveRec into the index*/
	KeyHash=HashKey(Key, KeyLen);
	
	if (SBins[KeyHash].NumInBin==MAX_SAVES_PER_BIN){
		printf("No more room in this bin\n");
		/*TODO: free up everything*/
	}else{
		SBins[KeyHash].Items[SBins[KeyHash].NumInBin]=SaveID;
		SBins[KeyHash].NumInBin++;
	}
	
	/*increment the save count*/
	Globals.Packets[PacketSlot].SaveCount++;
	
	/*unlock the save structures*/
	hlbr_mutex_unlock(&Globals.Packets[PacketSlot].Mutex);
	hlbr_mutex_unlock(&SavedMutex);
	
	return TRUE;
}

/**********************************************************
* Query for a particular key
**********************************************************/
SaveQuery* GetAndLockSavedPackets(char* Key, int KeyLen){
	unsigned short 	KeyHash;
	SaveQuery*		q;
	int				i;
	SaveRec*		s;
	
#ifdef DEBUGPATH
	printf("In GetAndLockSavedPackets\n");
#endif
	
	/*Set up the query*/
	KeyHash=HashKey(Key, KeyLen);
	q=calloc(sizeof(SaveQuery),1);
	q->NumResults=0;
	
	/*Lock the saved structs*/
	hlbr_mutex_lock(&SavedMutex, GET_SAVED_1, &SaveLockID);
	
	/*perform the query*/
	for (i=0;i<SBins[KeyHash].NumInBin;i++){
		s=&Saves[SBins[KeyHash].Items[i]];
	
		if (s->KeyLen==KeyLen)
		if (memcmp(s->Key, Key, KeyLen)==0){
			hlbr_mutex_lock(&s->Mutex, GET_SAVED_2, &s->LockID);		
			hlbr_mutex_lock(&Globals.Packets[s->PacketSlot].Mutex, GET_SAVED_3, &Globals.Packets[s->PacketSlot].LockID);
			
			q->Saves[q->NumResults]=SBins[KeyHash].Items[i];
			q->Packets[q->NumResults]=s->PacketSlot;
			q->NumResults++;
		
			if (q->NumResults==MAX_QUERY_RESULTS){
#ifdef DEBUG
				printf("Too Many results to fit in struct\n");
#endif		
				hlbr_mutex_unlock(&SavedMutex);
				return q;
			}
		}
	}
		
	/*unlock the saved structs*/
	hlbr_mutex_unlock(&SavedMutex);
		
#ifdef DEBUG
	printf("Query Returned %i results\n",q->NumResults);
#endif	
	
	return q;
}

/***********************************************
* Unlock everything, but keep saving the packets
************************************************/
void UnlockSavedQuery(SaveQuery* q){
	int		i;
#ifdef DEBUGPATH
	printf("in UnlockSavedQuery\n");
#endif
	
	if (!q) return;
	
	/*lock the saved structs*/
	hlbr_mutex_lock(&SavedMutex, UNLOCK_SAVED_1, &SaveLockID);
	
	/*iterate through and unlock*/
	for (i=0;i<q->NumResults;i++){
		hlbr_mutex_unlock(&Globals.Packets[Saves[q->Saves[i]].PacketSlot].Mutex);
		hlbr_mutex_unlock(&Saves[q->Saves[i]].Mutex);
	}
	
	/*unlock the saved structs*/
	hlbr_mutex_unlock(&SavedMutex);
	
	free(q);
}

