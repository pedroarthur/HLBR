#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#if 0
#define DEBUG
#define DEBUGPATH 1
#endif

#include "hlbrlib.h"

/*********************/ 
/* STRING FUNCTIONS */
/*******************/ 

char *RmSpace(char *s){

    char *p;
    /* wipe start & end of string */
    for (p = s + strlen(s) - 1; ((isspace(*p)) && (p >= s)); p--);
    if (p != s + strlen(s) - 1)
        *(p + 1) = 0;
    for (p = s; ((isspace(*p)) && (*p)); p++);
    if (p != s)
        strcpy(s, p);
    return (char *) s;
}

/* 
  This function would be called from a ParseArgs action.
  Returns: allocated buffer that must be freed on success
  Returns: NULL on error or if the option did not match.
*/

char *ParseCmp(char *name, char *buf)
{
    char opt[255];

    if (!buf[0] || !name[0])
	return NULL;

    snprintf(opt, sizeof(opt), "%s=", name);
    if (strncasecmp(buf, opt, strlen(name) + 1) == 0) {
        DBG((printf
             ("%s(%s->%s) \n", __FUNCTION__, name,
              (strchr(buf, '=') + 1))));
        return (char *) strdup(strchr(buf, '=') + 1);
    }
    return NULL;  
}
/*************************/
/* END STRING FUNCTIONS */
/***********************/


/**********************/
/*** LINKED LISTS  ***/
/********************/

/* 
 Add something to a list queue or create it 
 if it does not already exist.
*/

QueueList *ListAdd(char *ss, QueueList *q, char separator)
{
   QueueList *ll, *z;
   char *s, *ptr, *p;

   s = strdup(ss);
   ptr = (char *) MALLOC(strlen(ss));

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
      ll = (QueueList *) MALLOC(sizeof(QueueList));
      ll->next = NULL;
      ll->item = (char *) MALLOC(strlen(s) + 1);
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
   }
   while (s[0]);

   FREE(s);
   FREE(ptr);
   return q;
}

/* remove an item from a list queue */
QueueList *ListDel(char *s, QueueList *q, int *retval)
{
   QueueList *ll, *list, *old;

   ll = q;
   list = q;
   old = q;
   *retval = 0;

   while (ll != NULL) {
      if (strcasecmp(ll->item, s) == 0) {
	 if (ll == list) {
	    list = (ll->next);
	    FREE(ll->item);
	    FREE(ll);
	    ll = list;
	 } else {
	    old->next = ll->next;
	    FREE(ll->item);
	    FREE(ll);
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

/* clear out a list */
void ListClear(QueueList *list)
{
   QueueList *ll, *q;
   ll = list;
   while (ll != NULL) {
      q = ll->next;
      FREE(ll->item);
      FREE(ll);
      ll = q;
   }
}
