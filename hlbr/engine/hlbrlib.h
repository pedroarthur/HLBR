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


/**********/
/* MACROS */
/**********/

#define ARRAYSIZE(array) (sizeof(array)/sizeof(array[0]))

#define MALLOC malloc

#define FREE(x) { \
  if (x != NULL) { \
    free(x); \
  } else { \
    DBG((printf("Attempting to free a NULL pointer at 0x%x\n", x))); \
  } \
}

#define FREE_IF(x) { \
  if (x != NULL) { \
    free(x); \
  } \
}


#ifdef HLBR_LITTLE_ENDIAN
#define IP_BYTES(IP)	(IP & 0x000000ff), (IP & 0x0000ff00)>>8, (IP & 0x00ff0000)>>16, IP>>24
#else
#define IP_BYTES(IP)	IP>>24, (IP & 0x00ff0000)>>16, (IP & 0x0000ff00)>>8, (IP & 0x000000ff)
#endif

#endif /* _HLBR_LIB_H_ */
