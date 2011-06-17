//#define DEBUG
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "hlbr.h"
#include "hlbrlib.h"

#include <errno.h>

#ifdef _LINUX_
	#define MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE_NP
#else
	#define MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE
#endif

/****************************/ 
/* STRING RELATED FUNCTIONS */
/****************************/ 

/**
 * Removes all spaces from the start and end of a string.
 */
char *RmSpace(char *s) {
	char *pa = s + strlen(s) - 1;
	char *pb = s;

	while (isspace(*pa) && pa >= s)
		pa--;

	if (pa != s + strlen(s) - 1)
		*(pa + 1) = 0;

	while (isspace(*pb) && *pb)
			pb++;

	if (pb != s)
		strcpy(s, pb);

	return (char *) s;
}

/**
 * This function would be called from a ParseArgs action.
 * Returns: allocated buffer that must be freed on success
 * Returns: NULL on error or if the option did not match.
 */

char *ParseCmp(char *name, char *buf) {
	char opt[255];

	if (!buf[0] || !name[0])
		return NULL;

	snprintf(opt, sizeof(opt), "%s=", name);

	if (strncasecmp(buf, opt, strlen(name) + 1) == 0) {
		DBG(
			PRINTERROR3("%s(%s->%s) \n", __FUNCTION__, name,
				(strchr(buf, '=') + 1)));

		return (char *) strdup(strchr(buf, '=') + 1);
	}
	return NULL;
}

/**********************/
/*** LINKED LISTS  ***/
/********************/

/**
 * Breaks up a string in a list and store it into a QueueList linked list.
 * The character defined by the 'separator' parameter is searched in the
 * string 'ss' and the elements in-between are copied as items in the list;
 * note that all elements will have any leading and trailing spaces removed
 * (with RmSpace()).
 * @see QueueList
 * @see RmSpace
 */
QueueList *ListAdd(char *ss, QueueList *q, char separator) {
	QueueList *ll, *z;
	char *s, *ptr, *p;

	s = strdup(ss);

	if (!s) {
		fprintf(stderr, "Couldn't allocate memory! (%s():%d)\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	ptr = (char *) malloc (strlen(ss));

	if (!ptr) {
		fprintf(stderr, "Couldn't allocate memory! (%s():%d)\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	do {
		p = strchr(s, separator);

		if (p != NULL) {
			*p = 0;
			p++;
			strcpy(ptr, p);
		} else
			*ptr = 0;

		RmSpace(s);
		RmSpace(ptr);

		ll = (QueueList *) malloc (sizeof(QueueList));

		if (!ll) {
			fprintf(stderr, "Couldn't allocate memory! (%s():%d)\n", __FUNCTION__, __LINE__);
			return NULL;
		}

		ll->next = NULL;

		ll->item = (char *) malloc (strlen(s)+1);

		if (!ll->item) {
			fprintf(stderr, "Couldn't allocate memory! (%s():%d)\n", __FUNCTION__, __LINE__);
			return NULL;
		}

		strcpy(ll->item, s);

		if (q == NULL)
			q = ll;
		else {
			z = q;

			while (z->next != NULL)
				z = z->next;

			z->next = ll;
		}

		*s = 0;
		strcpy(s, ptr);

	} while (s[0]);

	free(s);
	free(ptr);

	return q;
}

/**
 * Remove an item from a list queue.
 * @see QueueList
 * @see ListAdd
 */
QueueList *ListDel(char *s, QueueList *q, int *retval) {
	QueueList *ll, *list, *old;

	ll = q;
	list = q;
	old = q;
	*retval = 0;

	while (ll != NULL) {
		if (strcasecmp(ll->item, s) == 0) {
			if (ll == list) {
				list = (ll->next);

				if (ll->item)
					free(ll->item);

				free(ll);

				ll = list;
			} else {
				old->next = ll->next;

				if (ll->item)
					free(ll->item);

				free(ll);

				ll = old->next;
			}

			*retval = 1;
		} else {
			old = ll;
			ll = ll->next;
		}
	}

	return list;
}

/**
 * Clear out a list
 */
void ListClear(QueueList *list) {
	QueueList *ll, *q;
	ll = list;

	while (ll != NULL) {
		q = ll->next;

		if (ll->item)
			free(ll->item);

		free(ll);

		ll = q;
	}
}

/********************************/
/* END STRING RELATED FUNCTIONS */
/********************************/

/**
 * Generic memory buffer dump functions
 */
void DumpBuffer(unsigned char *data, int size, FILE *stream) {
	int i;

	if (data == NULL || size <= 0)
		return;

	for (i=0; i < size; i++)
		putc((data[i] >= 32 && data[i] <=127 ? data[i] : '.'), stream);
}

  /***************************************/
 /* Generic thread-safe data structures */
/***************************************/

/*
 * Generic node
 */
Node* NodeNew (void* value) {
	Node* rvalue = (void *) calloc (1, sizeof(Node));
	rvalue->p = value;

	return rvalue;
}

void NodeDestroy (Node* node, void (*pfree)(void *p)) {
	if (node->p && pfree)
		pfree (node->p);

	free (node);
	return;
}

void* NodeGetData (Node* node) {
	if (node)
		return node->p;

	return NULL;
}

void NodeSetData (Node* node, void* data) {
	if (node)
		node->p = data;

	return;
}

/*
 * Queue
 */
Queue* QueueNew () {
	Queue* q = (Queue *) calloc (1, sizeof(Queue));

	if (q) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutexattr_settype (&attr, MUTEX_RECURSIVE);

		pthread_mutex_init (&q->mutex, &attr);

		pthread_mutexattr_destroy (&attr);

		sem_init (&q->semaphore, 0, 0);

		return q;
	}

	return NULL;
}

void QueueAddDestroyHandler (Queue* q, void (*pfree)(void* p)) {
	q->pfree = pfree;
}

void QueueDestroy (Queue* q) {
	while (q->size)
		NodeDestroy (QueueGetNode(q), q->pfree);

	free (q);
}

int QueueAddNewNode (Queue* q, void* data) {
	if (!QueueAddNode (q, NodeNew(data)))
		return FALSE;

	return TRUE;
}

int QueueAddNode (Queue* q, Node* node) {
	if (!node)
		return FALSE;

	pthread_mutex_lock (&q->mutex);

	if (!q->size) {
		q->first = node;
		q->last = q->first;
	} else {
		q->last->next = node;
		q->last = q->last->next;
	}

	node->next = NULL;
	q->size++;

	pthread_mutex_unlock (&q->mutex);
	return TRUE;
}

void* QueueGetData (Queue* q) {
	pthread_mutex_lock (&q->mutex);

	if (q->size) {
		Node *node = QueueGetNode (q);
		pthread_mutex_unlock (&q->mutex);

		void* rvalue = NodeGetData (node);

		NodeDestroy (node, NULL);

		return rvalue;
	}

	pthread_mutex_unlock (&q->mutex);
	return NULL;
}

Node* QueueGetNode (Queue* q) {
	pthread_mutex_lock (&q->mutex);

	if (q->size) {
		Node *rvalue = q->first;
		q->first = q->first->next;

		if (!q->first)
			q->last = NULL;

		q->size--;
		pthread_mutex_unlock (&q->mutex);

		rvalue->next = NULL;

		return rvalue;
	}

	pthread_mutex_unlock (&q->mutex);
	return NULL;
}

int QueuePost (Queue* q) {
	if (sem_post(&q->semaphore))
		return FALSE;
	else
		return TRUE;
}

int QueueWait (Queue* q) {
	while (TRUE) {
		switch (sem_wait(&q->semaphore)) {
			case EINTR:
#ifdef DEBUG
				fprintf(stderr, "%s: Wait Interrupted\n", __FUNCTION__);
#endif
				break;
			case EINVAL:
				fprintf (stderr, "Waiting on a invalid semaphore!\n");
				return FALSE;
			default:
				return TRUE;
		}
	}

	return FALSE;
}

int QueueGetSize (Queue* q) {
	int size;

	pthread_mutex_lock (&q->mutex);

	size = q->size;

	pthread_mutex_unlock (&q->mutex);
	return size;
}

/*
 * Stack
 */

Stack* StackNew () {
	Stack* s = (Stack*) calloc (1, sizeof(Stack));

	if (s) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutexattr_settype (&attr, MUTEX_RECURSIVE);

		pthread_mutex_init (&s->mutex, &attr);

		pthread_mutexattr_destroy (&attr);

		sem_init (&s->semaphore, 0, 0);

		return s;
	}

	return NULL;
}

void StackAddDestroyHandler (Stack* s, void (*pfree)(void*)) {
	s->pfree = pfree;
}

void StackDestroy (Stack* s) {
	while (s->size)
		NodeDestroy (StackPopNode(s), s->pfree);

	free (s);

	return;
}

int StackPushData (Stack* s, void* data) {
	if (!StackPushNode (s, NodeNew(data)))
		return FALSE;

	return TRUE;
}

int StackPushNode (Stack* s, Node* node) {
	if (!node)
		return FALSE;

	pthread_mutex_lock (&s->mutex);
	node->next = s->top;
	s->top = node;

	s->size++;

	pthread_mutex_unlock (&s->mutex);
	return TRUE;
}

void* StackPopData (Stack* s) {
	pthread_mutex_lock (&s->mutex);

	if (s->size) {
		Node* node = StackPopNode (s);
		pthread_mutex_unlock (&s->mutex);

		void* rvalue = NodeGetData(node);

		NodeDestroy (node, NULL);

		return rvalue;
	}

	pthread_mutex_unlock (&s->mutex);
	return NULL;
}

Node* StackPopNode (Stack* s) {
	pthread_mutex_lock (&s->mutex);

	if (s->size) {
		Node* rvalue = s->top;
		s->top = s->top->next;

		s->size--;
		pthread_mutex_unlock (&s->mutex);

		rvalue->next = NULL;
		return rvalue;
	}

	pthread_mutex_unlock (&s->mutex);
	return NULL;
}

int StackPost (Stack* s) {
	if (sem_post(&s->semaphore))
		return FALSE;
	else
		return TRUE;
}

int StackWait (Stack* s) {
	while (TRUE) {
		switch (sem_wait(&s->semaphore)) {
			case EINTR:
#ifdef DEBUG
				fprintf(stderr, "%s: Wait Interrupted\n", __FUNCTION__);
#endif
				break;
			case EINVAL:
				fprintf (stderr, "Waiting on a invalid semaphore!\n");
				return FALSE;
			default:
				return TRUE;
		}
	}

	return FALSE;
}

int StackGetSize (Stack* s) {
	int size;

	pthread_mutex_lock (&s->mutex);

	size = s->size;

	pthread_mutex_unlock (&s->mutex);
	return size;
}

/*
 * Hash Table
 */

HashNode *HashNodeNew () {
	HashNode *n = (HashNode *) calloc (1, sizeof(HashNode));
	return n;
}

void HashNodeDestroy(HashNode *n) {
	free(n);
}

HashCache *HashCacheNew(int n) {
	int i,j;
	HashCache *c = (HashCache *) malloc (sizeof(HashCache));

	if (c == NULL)
		return NULL;

	c->Nodes = (HashNode **) calloc (n, sizeof(HashNode*));

	if (c->Nodes == NULL)
		return NULL;

	for (i = 0 ; i < n ; i++) {
		c->Nodes[i] = HashNodeNew();

		if (c->Nodes[i] == NULL) {
			for (j = 0 ; j < i ; j++)
				HashNodeDestroy(c->Nodes[j]);

			free(c->Nodes);
			free(c);

			return NULL;
		}
	}

	c->NodeCount = n;
	c->CurrPos = 0;

	pthread_mutex_init(&c->Lock, NULL);

	return c;
}

void HashCacheDestroy(HashCache *c) {
	int i;

	for (i = c->CurrPos ; i < c->NodeCount ; i++)
		HashNodeDestroy(c->Nodes[i]);

	pthread_mutex_destroy(&c->Lock);

	free(c->Nodes);
	free(c);
}

HashNode *HashCacheGet(HashCache *c) {
	HashNode *r = NULL;

	pthread_mutex_lock(&c->Lock);

	if ((c != NULL) && (c->CurrPos < c->NodeCount))
		r = c->Nodes[c->CurrPos++];

	pthread_mutex_unlock(&c->Lock);

	return r;
}

int HashCachePut(HashCache *c, HashNode *n) {
	int r = FALSE;

	pthread_mutex_lock(&c->Lock);

	if ((c != NULL) && (c->CurrPos > 0)) {
		c->Nodes[--c->CurrPos] = n;
		r = TRUE;
	}

	pthread_mutex_unlock(&c->Lock);

	return r;
}

HashTable *HashTableCreate(int size,
				int (*hashFunction)(void *key),
				int (*compareFunction)(void *k, void *l))
{
	int i;
	HashTable *h = (HashTable *) calloc (1, sizeof(HashTable));

	if (h == NULL)
		return NULL;

	h->Size = size;
	h->STime = 0xFFFFFFFF;

	h->HashFunction = hashFunction;
	h->CompareFunction = compareFunction;

	h->Keys = (HashNode **) calloc (h->Size, sizeof(HashNode *));

	if (h->Keys == NULL) {
		free(h);
		return NULL;
	}

	h->KLocks = (pthread_mutex_t *) calloc (h->Size, sizeof(pthread_mutex_t));

	if (h->KLocks == NULL) {
		free(h->Keys);
		free(h);

		return NULL;
	}

	for (i = 0 ; i < size ; i++)
		pthread_mutex_init(&h->KLocks[i], NULL);

	pthread_cond_init(&h->RWaiter, NULL);
	pthread_cond_init(&h->CWaiter, NULL);
	pthread_mutex_init(&h->GLock, NULL);
	/* TODO: Initialize the specific data 'transactioning'*/

	h->State = FREE;
	h->RCount = 0;

	return h;
}

int HashTablePreCache(HashTable *h, int n) {
	return (h->Cache = HashCacheNew(h->Size * n)) ? TRUE : FALSE;
}

void HashTableDestroy(HashTable *h) {
	HashNode *a, *b;
	int i;

	for (i = 0 ; i < h->Size ; i++) {
		for (a = h->Keys[i] ; a ; a = b) {
			if (h->DataFree && a->Data)
				h->DataFree(a->Data);

			if (h->KeyFree && a->Key)
				h->KeyFree(a->Key);

			b = a->chain;
			HashNodeDestroy(a);
		}

		pthread_mutex_destroy(&h->KLocks[i]);
	}

	if (h->Cache)
		HashCacheDestroy(h->Cache);

	pthread_mutex_destroy(&h->GLock);
	pthread_cond_destroy(&h->RWaiter);
	pthread_cond_destroy(&h->CWaiter);

	free(h->KLocks);
	free(h->Keys);
	free(h);
}

void HashTableTransactionBegin(HashTable *h) {
	pthread_mutex_lock(&h->GLock);

	if (h->State == READING) {
		h->State = LOCKED;
		pthread_cond_wait(&h->CWaiter, &h->GLock);
	}

	pthread_setspecific(h->Transactioning, (void*) 0x01);
}

void HashTableTransactionEnd(HashTable *h) {
	h->State = FREE;
	pthread_setspecific(h->Transactioning, NULL);

	pthread_cond_broadcast(&h->RWaiter);
	pthread_mutex_unlock(&h->GLock);
}

void HashTableStartReading(HashTable *h) {
	if (pthread_getspecific(h->Transactioning) != NULL)
		return;

	pthread_mutex_lock(&h->GLock);

	while (h->State == LOCKED)
		pthread_cond_wait(&h->RWaiter, &h->GLock);

	if (h->State == FREE)
		h->State = READING;

	h->RCount++;

	pthread_mutex_unlock(&h->GLock);
}

void HashTableStopReading(HashTable *h) {
	if (pthread_getspecific(h->Transactioning) != NULL)
		return;

	pthread_mutex_lock(&h->GLock);

	if (--h->RCount == 0) {
		if (h->State == READING)
			h->State = FREE;
		else
			pthread_cond_signal(&h->CWaiter);
	}

	pthread_mutex_unlock(&h->GLock);
}

void *HashTableInsert(HashTable *h, void *key, void *data) {
	HashNode *a;
	int hashEntry = h->HashFunction(key);

	HashTableStartReading(h);
	pthread_mutex_lock(&h->KLocks[hashEntry]);

	for (a = h->Keys[hashEntry] ; a ; a = a->chain)
		if (h->CompareFunction(a->Key, key)) {
			pthread_mutex_unlock(&h->KLocks[hashEntry]);
			HashTableStopReading(h);

			time(&a->CTime);
			return a->Data;
		}

	if ((a = HashCacheGet(h->Cache)) == NULL)
		a = HashNodeNew();

	if (a == NULL) {
		pthread_mutex_unlock(&h->KLocks[hashEntry]);
		HashTableStopReading(h);

		return NULL;
	}

	a->chain = h->Keys[hashEntry];
	h->Keys[hashEntry] = a;

	a->CTime = time(NULL);
	a->Data = data;
	a->Key = key;

	pthread_mutex_unlock(&h->KLocks[hashEntry]);
	HashTableStopReading(h);

	return a->Data;
}

int HashTableHasKey(HashTable *h, void *key) {
	HashNode *a;
	int hashEntry = h->HashFunction(key);

	HashTableStartReading(h);
	pthread_mutex_lock(&h->KLocks[hashEntry]);

	for (a = h->Keys[hashEntry] ; a ; a = a->chain)
		if (h->CompareFunction(a->Key, key))
			break;

	pthread_mutex_unlock(&h->KLocks[hashEntry]);
	HashTableStopReading(h);

	if (a != NULL)
		return TRUE;
	else
		return FALSE;
}

void *HashTableRemove(HashTable *h, void *key) {
	HashNode	*a,
				*b = NULL;
	void		*data = NULL;
	int 		hashEntry = h->HashFunction(key);

	HashTableStartReading(h);
	pthread_mutex_lock(&h->KLocks[hashEntry]);

	for (a = h->Keys[hashEntry] ; a ; b = a, a = a->chain) {
		if (!h->CompareFunction(a->Key,key))
			continue;

		data = a->Data;

		if (b != NULL)
			b->chain = a->chain;
		else
			h->Keys[hashEntry] = NULL;

		if (h->KeyFree != NULL)
			h->KeyFree(a->Key);

		if (!HashCachePut(h->Cache, a))
			HashNodeDestroy(a);

		break;
	}

	pthread_mutex_unlock(&h->KLocks[hashEntry]);
	HashTableStopReading(h);

	return data;
}

void* HashTableKeeper(void *v) {
	int			 i = 0;
	HashTable	*h = (HashTable *) v;
	HashNode	*n = NULL,
				*p = NULL,
				*f = NULL;
	time_t		 t = time(NULL);

	HashTableTransactionBegin(h);

	for (i = 0 ; i < h->Size ; i++) {
		p = NULL;
		n = h->Keys[i];

		while (n != NULL) {
			if (t - n->CTime < h->STime) {
				p = n;
				n = n->chain;

				continue;
			}

			f = n;

			if (h->DataFree != NULL)
				h->DataFree(n->Data);

			if (h->KeyFree != NULL)
				h->KeyFree(n->Key);

			if (p != NULL)
				n = p->chain = n->chain;
			else
				n = h->Keys[i] = n->chain;

			if (HashCachePut(h->Cache, f) != TRUE)
				HashNodeDestroy(f);
		}
	}

	HashTableTransactionEnd(h);
}

#ifdef DEBUG
#undef DEBUG
#endif
