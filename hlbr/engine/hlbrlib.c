//#define DEBUG
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "hlbr.h"
#include "hlbrlib.h"

#include <errno.h>

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

  /**************************************/
 /* Generic thread-safe data structures /
/**************************************/

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
		int kind;
#ifdef _LINUX_
		kind = PTHREAD_MUTEX_RECURSIVE_NP;
#else
		kind = PTHREAD_MUTEX_RECURSIVE;
#endif

		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutexattr_setkind_np (&attr, kind);

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
		int kind;
#ifdef _LINUX_
		kind = PTHREAD_MUTEX_RECURSIVE_NP;
#else
		kind = PTHREAD_MUTEX_RECURSIVE;
#endif

		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutexattr_setkind_np (&attr, kind);

		pthread_mutex_init (&s->mutex, &attr);

		pthread_mutexattr_destroy (&attr);

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

int StackGetSize (Stack* s) {
	int size;

	pthread_mutex_lock (&s->mutex);

	size = s->size;

	pthread_mutex_unlock (&s->mutex);
	return size;
}

#ifdef DEBUG
#undef DEBUG
#endif
