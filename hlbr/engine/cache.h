#ifndef HLBR_CACHE_H
#define HLBR_CACHE_H

#include "../config.h"
#include "hlbr.h"

#define CACHE_MAX_KEYS			256
#define CACHE_MAX_ITEMS_PER_KEY		64
#define CACHE_NONE			-1

typedef struct cache_item{
	unsigned char*	Data;
	unsigned int	DataLen;
}CacheItem;

typedef struct cache_items{
	unsigned char*	Key;
	int		KeyLen;

	CacheItem	Items[CACHE_MAX_ITEMS_PER_KEY];
	unsigned int	NumItems;

	long		LastTime;
}CacheItems;

typedef struct cache{
	CacheItems	Keys[CACHE_MAX_KEYS];
	unsigned int	NumKeys;

	void (*Free)	(void *pointer);

	long		TimeoutLen;
} Cache;

Cache* InitCache(int TimeoutLen, void (*Free)(void *));
int CacheAdd(Cache* c, unsigned char* Key, int KeyLen, unsigned char* Data, int DataLen, int Now);
int CacheDelKey(Cache* c, unsigned char* Key, int KeyLen, int Now);
CacheItems* CacheGet(Cache* c, unsigned char* Key, int KeyLen, int Now);
void DestroyCache(Cache* c);



#endif
