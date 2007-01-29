#ifndef _HLBR_LIB_H_
#define _HLBR_LIB_H_


/* Used to queue a lot of things */
struct queue_t {
   char *item;
   struct queue_t *next;
};
typedef struct queue_t QueueList;

/**************/
/* Prototypes */
/**************/
char *ParseCmp(char *,char *);
char *RmSpace(char *);
QueueList *ListAdd(char *,QueueList *, char);
QueueList *ListDel(char *,QueueList *,int *);
void ListClear(QueueList *);

#endif /* _HLBR_LIB_H_ */
