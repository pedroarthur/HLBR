#ifndef _HLBR_LIB_H_
#define _HLBR_LIB_H_

#include <stdio.h>


/**
 * Generic linked list struct for strings.
 * Used to queue a lot of things along the code
 */
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
FILE* LogFile(LogFileRec*);
void CloseLogFile(LogFileRec*);
int LogMessage(char*, void*);

char *ParseCmp(char *,char *);
char *RmSpace(char *);

QueueList *ListAdd(char *,QueueList *, char);
QueueList *ListDel(char *,QueueList *,int *);
void ListClear(QueueList *);

void DumpBuffer(char *, int);

#endif /* _HLBR_LIB_H_ */
