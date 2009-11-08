#include "cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//#define DEBUG

/***************************************
* Set up a new cache
***************************************/
Cache* InitCache(int TimeoutLen){
	Cache*		NewCache;

	DEBUGPATH;

	NewCache = calloc(sizeof(Cache),1);
	NewCache->TimeoutLen = TimeoutLen;

	return NewCache;
}

/**********************************************
* Given a Key, find the Cache bin
**********************************************/
int CacheGetBin(Cache* c, unsigned char* Key, int KeyLen){
	int		i;

#ifdef DEBGUPATH
	printf("In CacheGetBin\n");
#endif

	for (i=0;i<c->NumKeys;i++){
		if (c->Keys[i].KeyLen==KeyLen){
			if (memcmp(c->Keys[i].Key, Key, KeyLen)==0){
				return i;
			}
		}
	}

	return CACHE_NONE;
}

/*********************************************
* Create a new bin to put stuff in
*********************************************/
int CacheCreateBin(Cache* c, unsigned char* Key, int KeyLen){

DEBUGPATH;

	/*check to see if we're full*/
	if (c->NumKeys>=CACHE_MAX_KEYS){
#ifdef DEBUG
		printf("Cache is full\n");
#endif
		return CACHE_NONE;
	}

	/*allocate a new one*/
	c->Keys[c->NumKeys].Key=malloc(KeyLen);
	memcpy(c->Keys[c->NumKeys].Key, Key, KeyLen);
	c->Keys[c->NumKeys].KeyLen=KeyLen;
	c->Keys[c->NumKeys].NumItems=0;

	c->NumKeys++;

	return c->NumKeys-1;
}


/*********************************************
* put a new item in a cache bin
*********************************************/
int CacheBinAdd(CacheItems* ci, unsigned char* Data, int DataLen){

DEBUGPATH;

	if (ci->NumItems==CACHE_MAX_ITEMS_PER_KEY){
#ifdef DEBUG
		printf("This key if full\n");
#endif
		return FALSE;
	}

	ci->Items[ci->NumItems].Data=malloc(DataLen);
	memcpy(ci->Items[ci->NumItems].Data, Data, DataLen);
	ci->Items[ci->NumItems].DataLen=DataLen;

	ci->NumItems++;

	return TRUE;
}

/************************************************
* Kill any keys that have timed out
************************************************/
void CacheTimeout(Cache* c, int Now){
	int		i;

	DEBUGPATH;

	for (i=0;i<c->NumKeys;i++){
		if ( (c->Keys[i].LastTime+c->TimeoutLen) < Now){
			CacheDelKey(c, c->Keys[i].Key, c->Keys[i].KeyLen, 0);
		}
	}
}


/*********************************************
* Put some data into the cache
*********************************************/
int CacheAdd(Cache* c, unsigned char* Key, int KeyLen, unsigned char* Data, int DataLen, int Now){
	int	BinID;

	DEBUGPATH;

	/*go find the bin, if it exists*/
	BinID = CacheGetBin(c, Key, KeyLen);
	if (BinID == CACHE_NONE){
#ifdef DEBUG
		printf("First Item in this bin\n");
#endif
		BinID=CacheCreateBin(c, Key, KeyLen);
	}

	if (BinID == CACHE_NONE){
#ifdef DEBUG
		printf("Failed to create a new bin\n");
#endif
		return FALSE;
	}

	/*now add the key to that bin*/
	if (!CacheBinAdd(&c->Keys[BinID], Data, DataLen)){
#ifdef DEBUG
		printf("Failed to add to key. full?\n");
#endif
		return FALSE;
	}

	c->Keys[BinID].LastTime = Now;

	CacheTimeout(c, Now);

	return TRUE;
}

/************************************************
* We're done with this key, kill it
*************************************************/
int CacheDelKey(Cache* c, unsigned char* Key, int KeyLen, int Now){
	int		KeyID;
	int		i;
	CacheItems*	ci;

	DEBUGPATH;

	/*go find the bin*/
	KeyID = CacheGetBin(c, Key, KeyLen);
	if (KeyID == CACHE_NONE){
#ifdef DEBUG
		printf("There is no such key\n");
#endif
		return FALSE;
	}

	/*get rid of the items in that bin*/
	ci = &c->Keys[KeyID];

	for (i = 0; i < ci->NumItems ; i++){
		if (ci->Items[i].Data)
			free(ci->Items[i].Data);

		ci->Items[i].Data = NULL;
		ci->Items[i].DataLen = 0;
	}

	/*get rid of the bin*/
	if (ci->Key)
		free(ci->Key);

	ci->Key = NULL;
	ci->KeyLen = 0;
	ci->NumItems = 0;

	/*move everything up*/
	memcpy(&c->Keys[KeyID], &c->Keys[KeyID+1], sizeof(CacheItems) * (c->NumKeys-KeyID));
	c->NumKeys--;

	CacheTimeout(c, Now);

	return TRUE;
}

/********************************************
* Retrieve the contents of the key
********************************************/
CacheItems* CacheGet(Cache* c, unsigned char* Key, int KeyLen, int Now){
	int	KeyID;
	
	DEBUGPATH;

	KeyID = CacheGetBin(c, Key, KeyLen);
	if (KeyID == CACHE_NONE){
#ifdef DEBUG
		printf("No Such key\n");
#endif	
		return NULL;
	}
	
	CacheTimeout(c, Now);
	
	return &c->Keys[KeyID];
}

/***************************************************
* We're all done with this cache, free everything
***************************************************/
void DestroyCache(Cache* c){
	int i,j;

	DEBUGPATH;

	for (i = 0; i < c->NumKeys ; i++){
		for (j = 0; j < c->Keys[i].NumItems ; j++){
			if (c->Keys[i].Items[j].Data)
				free(c->Keys[i].Items[j].Data);
		}

		if (c->Keys[i].Key)
			free(c->Keys[i].Key);
	}
	
	free(c);
	c = NULL;
}
