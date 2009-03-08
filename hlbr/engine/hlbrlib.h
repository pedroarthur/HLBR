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
int QueueAddNewNode (Queue* q, void* value);
int QueueAddNode (Queue* q, Node* node);

/* Retrieving */
void* QueueGetData (Queue* q);
Node* QueueGetNode (Queue* q);

/* Synchonization */
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
} Stack;

Stack* StackNew ();

void StackAddDestroyHandler (Stack* s, void (*pfree)(void*));
void StackDestroy (Stack* s);

int StackPushData (Stack* s, void* data);
int StackPushNode (Stack* s, Node* node);

void* StackPopData (Stack* s);
Node* StackPopNode (Stack* s);

int StackGetSize (Stack* s);

#endif /* _HLBR_LIB_H_ */
