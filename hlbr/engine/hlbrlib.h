#ifndef _HLBR_HOGLIB_H_
#define _HLBR_HOGLIB_H_


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

#ifdef DEBUG
#define DBG(a)  a
#else           /* !DEBUG */
#define DBG(a)  /* do nothing! */
#endif          /* DEBUG */

#ifdef DEBUGPATH
#undef DEBUGPATH
#define DEBUGPATH printf("In %s() on line %d\n", __FUNCTION__, __LINE__)
#else
#define DEBUGPATH ;
#endif /* DEBUGPATH */

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


#endif /* _HLBR_HOGLIB_H_ */
