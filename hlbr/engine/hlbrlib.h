#ifndef _HLBR_LIB_H_
#define _HLBR_LIB_H_

#include <stdio.h>

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

#endif /* _HLBR_LIB_H_ */
