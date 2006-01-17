#ifndef HOGWASH_NUM_LIST_H
#define HOGWASH_NUM_LIST_H

#include "../config.h"

/********************************************
* Normal lists just hold lists of numbers
* time lists entries timeout at time XXXX
* age lists timeout when entries aren't used after XXXX sec
* paired lists are unique pairs of values
*********************************************/

#define LIST_TYPE_NORMAL	1
#define LIST_TYPE_TIME		2
#define LIST_TYPE_AGE		3
#define LIST_TYPE_PAIRED	4

#define LIST_INITIAL_SIZE	10
#define LIST_GROW_SIZE		50

struct num_list;
struct paired_list;

typedef struct num_alias_item{
	char			Alias[512];
	unsigned int	Num;
} NumAlias;

typedef struct num_list_item{
	struct num_list*		SubList;
	unsigned int 			Lower;
	unsigned int 			Upper;
	int						Time;
} NumItem;

typedef struct num_list{
	char		ListType;
	int			Timeout;
	NumItem**	Items;
	int			NumEntries;
	int			AllocCount;
} NumList;

NumList* InitNumList(int ListType);
void DestroyNumList(NumList* n);
int ClearNumList(NumList* n);
int AddRange(NumList* n, unsigned int Lower, unsigned int Upper);
int AddRangeTime(NumList* n, unsigned int Lower, unsigned int Upper, int Time);
int AddSubList(NumList* n, NumList* SubList);
int IsInList(NumList* n, unsigned int Number);
int IsInListTime(NumList* n, unsigned int Number, int Now);
int AddRangesString(NumList* n, char* Ranges, NumAlias* Aliases, int NumAliases);
int AddIPRanges(NumList* n, char* Ranges);
int RemoveFromList(NumList* n, unsigned int Number);
int NumListCompare(NumList* n1, NumList* n2);

#endif
