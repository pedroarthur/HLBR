#ifndef _HLBR_LIB_H_
#define _HLBR_LIB_H_

#include <stdio.h>

#include <pthread.h>
#include <semaphore.h>

/**
 * Generic linked list struct for strings.
 * Used to queue a lot of things along the code
 */
typedef struct queue_t {
   char *item;
   struct queue_t *next;
} QueueList;

char *ParseCmp(char *,char *);
char *RmSpace(char *);

QueueList *ListAdd(char *,QueueList *, char);
QueueList *ListDel(char *,QueueList *,int *);
void ListClear(QueueList *);

void DumpBuffer(unsigned char *, int, FILE *);

/**
 * Generic Node data structure
 * Used at implementations of Queue and Stack
 */

typedef struct node {
	void *p;
	struct node *next;
} Node;

Node* NodeNew (void* value);
void NodeDestroy (Node* node, void (*pfree)(void *p));
void* NodeGetData (Node* node);
void NodeSetData (Node* node, void* data);

typedef struct queue {
	Node *first;
	Node *last;
	int size;

	void (*pfree)(void* p);

	pthread_mutex_t mutex;
	sem_t semaphore;
} Queue;

/* Creation */
Queue* QueueNew ();

/* Destruction */
void QueueAddDestroyHandler (Queue* q,void (*pfree)(void *p));
void QueueDestroy (Queue* q);

/* Populating */
int QueueAddData (Queue* q, void* value);
int QueueAddNode (Queue* q, Node* node);

/* Retrieving */
void* QueueGetData (Queue* q);
Node* QueueGetNode (Queue* q);

/* Synchronization */
int QueueLock (Queue* q);
int QueueUnlock (Queue* q);

int QueuePost (Queue* q);
int QueueWait (Queue* q);

/* Misc */
int QueueGetSize (Queue* q);

typedef struct stack {
	Node* top;
	int size;

	void (*pfree)(void*);

	pthread_mutex_t mutex;
	sem_t semaphore;
} Stack;

/* Stack creation */
Stack* StackNew ();

/* Stack Destruction */
void StackAddDestroyHandler (Stack* s, void (*pfree)(void*));
void StackDestroy (Stack* s);

/* Pushing Data  */
int StackPushData (Stack* s, void* data);
int StackPushNode (Stack* s, Node* node);

/* Popping Data */
void* StackPopData (Stack* s);
Node* StackPopNode (Stack* s);

/* Synchronization */
int StackLock (Stack* s);
int StackUnlock (Stack* s);

int StackPost (Stack* s);
int StackWait (Stack* s);

/* Misc */
int StackGetSize (Stack* s);

/**
 * Concurrent hash table implementation
 */
typedef struct hashNode {
	void *Data;
	void *Key;

	time_t CTime;

	struct hashNode *chain;
} HashNode;

HashNode *HashNodeNew ();
void HashNodeDestroy(HashNode *n);

typedef struct {
	HashNode	**Nodes;

	int			NodeCount;
	int			CurrPos;

	pthread_mutex_t Lock;
} HashCache;

HashCache *HashCacheNew(int n);
void HashCacheDestroy(HashCache *c);
HashNode *HashCacheGet(HashCache *c);
int HashCachePut(HashCache *c, HashNode *n);

typedef struct {
	HashNode	**Keys;
	HashCache	*Cache;

	int Size;

	time_t STime;

	int (*HashFunction)(void *);
	int (*CompareFunction)(void *, void *);

	void (*DataFree)(void *);
	void (*KeyFree)(void *);

	/* Concurrency kept vars */
	enum {
		FREE, READING, LOCKED, TRANSACTIONING
	} State;

	int RCount;

	pthread_key_t	 Transactioning;

	pthread_mutex_t *KLocks;
	pthread_mutex_t  GLock;

	pthread_cond_t   RWaiter;
	pthread_cond_t   CWaiter;
} HashTable;

HashTable *HashTableCreate(int size, int (*hashFunction)(void *key),
							int (*compareFunction)(void *k, void *l));
void HashTableDestroy(HashTable *h);
int HashTablePreCache(HashTable *h, int n);

int HashTableHasKey(HashTable *h, void *key);
void *HashTableInsert(HashTable *h, void *key, void *data);
void *HashTableRemove(HashTable *h, void *key);
void *HashTableKeeper(void *v);

#endif /* _HLBR_LIB_H_ */
