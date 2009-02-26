//#define DEBUG
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "hlbr.h"
#include "hlbrlib.h"

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

#ifdef DEBUG
#undef DEBUG
#endif
