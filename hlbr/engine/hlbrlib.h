#ifndef _HLBR_LIB_H_
#define _HLBR_LIB_H_

#include <stdio.h>


/* Used to queue a lot of things */
struct queue_t {
   char *item;
   struct queue_t *next;
};
typedef struct queue_t QueueList;


/**
 * Struct used to keep names/handlers/etc of log files.
 * This is mainly used by action alert file.
 */
typedef struct log_file_rec {
	char	fname[1024];
	FILE*	fp;
} LogFileRec;



/**************/
/* Prototypes */
/**************/
char *ParseCmp(char *,char *);
char *RmSpace(char *);
QueueList *ListAdd(char *,QueueList *, char);
QueueList *ListDel(char *,QueueList *,int *);
void ListClear(QueueList *);

#endif /* _HLBR_LIB_H_ */
