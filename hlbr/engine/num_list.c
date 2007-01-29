#include "num_list.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hlbr.h"

//#define DEBUG

extern GlobalVars Globals;

/*************************************
* Start up a number list
*************************************/
NumList* InitNumList(int ListType){
	NumList*	n;

	DEBUGPATH;

	n=calloc(sizeof(NumList),1);
	
	n->ListType=ListType;
	n->Items=calloc(sizeof(NumItem*),LIST_INITIAL_SIZE);
	n->AllocCount=LIST_INITIAL_SIZE;
	
	return n;
}

/******************************************
* Remove all the items from this number list
********************************************/
int ClearNumList(NumList* n){
	int		i;
	
	DEBUGPATH;

	for (i=0;i<n->NumEntries;i++){
		if (n->Items[i]){
			free(n->Items[i]);
			n->Items[i]=NULL;
		}
	}
	
	n->NumEntries=0;
	
	free(n->Items);
	n->Items=calloc(sizeof(NumItem*),LIST_INITIAL_SIZE);
	n->AllocCount=LIST_INITIAL_SIZE;
	
	return TRUE;
}

/***************************************
* Get rid of this number list
****************************************/
void DestroyNumList(NumList* n){
	DEBUGPATH;

	ClearNumList(n);
	if (n->Items){
		free(n->Items);
		n->Items=NULL;
	}
	free(n);
}

/***************************************
* add a range to this number list
* TODO: Check for overlaps
****************************************/
int AddRangeTime(NumList* n, unsigned int Lower, unsigned int Upper, int Time){
	NumItem*	i;
	NumItem**	new_items;
		
	DEBUGPATH;

	i=calloc(sizeof(NumItem),1);
	i->Lower=Lower;
	i->Upper=Upper;
	i->Time=Time;

	if (n->NumEntries==n->AllocCount){
#ifdef DEBUG
		printf("List is full, allocating more slots\n");
#endif	
		new_items=calloc(sizeof(NumItem*), n->AllocCount+LIST_GROW_SIZE);
		memcpy(new_items, n->Items, sizeof(NumItem*)*n->AllocCount);
		n->AllocCount+=LIST_GROW_SIZE;
		free(n->Items);
		n->Items=new_items;
	}
	
	n->Items[n->NumEntries]=i;
	n->NumEntries++;
	
	return TRUE;
}

/***************************************************
* Wrapper function for normal lists
****************************************************/
int AddRange(NumList* n, unsigned int Lower, unsigned int Upper){
	DEBUGPATH;

	return AddRangeTime(n,Lower, Upper, -1);
}

/***************************************************
* Add as sublist to this list
***************************************************/
int AddSubList(NumList* n, NumList* SubList){
	NumItem*	i;
	NumItem**	new_items;
		
	DEBUGPATH;

	i=calloc(sizeof(NumItem),1);
	i->Time=-1;	/*this item doesn't have a timeout*/
	i->SubList=SubList;

	if (n->NumEntries==n->AllocCount){
#ifdef DEBUG
		printf("2List is full, allocating more slots\n");
#endif	
		new_items=calloc(sizeof(NumItem*), n->AllocCount+LIST_GROW_SIZE);
		memcpy(new_items, n->Items, sizeof(NumItem*)*n->AllocCount);
		n->AllocCount+=LIST_GROW_SIZE;
		free(n->Items);
		n->Items=new_items;
	}
	
	n->Items[n->NumEntries]=i;
	n->NumEntries++;
	
	return TRUE;
}

/***************************************************
* Check to see if the number is in the list
****************************************************/
int IsInList(NumList* n, unsigned int Number){
	NumItem*	i;
	int			j;
	
	DEBUGPATH;

	for (j=0;j<n->NumEntries;j++){
		i=n->Items[j];
#ifdef DEBUG	
		printf("Checking for %u in %u-%u\n",Number, i->Lower, i->Upper);
#endif
		if (i->SubList){
			if (IsInList(i->SubList, Number)) return TRUE;
		}else if ( (i->Lower<=Number) && (i->Upper>=Number) ){
			return TRUE;
		}	
	}
	
	return FALSE;
}

/***************************************************
* Check to see if the number is in the list
* Time out entries as needed
****************************************************/
int IsInListTime(NumList* n, unsigned int Number, int Now){
	NumItem*	i;
	int			j;
	
	DEBUGPATH;

	if ((n->ListType!=LIST_TYPE_TIME) && (n->ListType!=LIST_TYPE_AGE)) return FALSE;

	for (j=0;j<n->NumEntries;j++){
		i=n->Items[j];
		
		/*see if this entry needs to be timed out*/
		if (i->Time!=-1){
			if (n->ListType==LIST_TYPE_TIME){
				if (i->Time < Now){
#ifdef DEBUG
					printf("Timing out item\n");
#endif				
					free(n->Items[j]);
					n->Items[j]=NULL;
					memmove(&n->Items[j],&n->Items[j+1], sizeof(NumItem*)*(n->NumEntries-j));
					n->Items[n->NumEntries]=NULL;
					n->NumEntries--;
					j--;
					continue;
				}
			}else if (n->ListType==LIST_TYPE_AGE){
				if (i->Time < (Now+n->Timeout)){
#ifdef DEBUG
					printf("2Timing out item\n");
#endif			
					free(n->Items[j]);
					n->Items[j]=NULL;
					memmove(&n->Items[j],&n->Items[j+1], sizeof(NumItem*)*(n->NumEntries-j));
					n->Items[n->NumEntries]=NULL;
					n->NumEntries--;				
					j--;
					continue;
				}		
			}
		}
		
#ifdef DEBUG	
		printf("Checking for %u in %u-%u\n",Number, i->Lower, i->Upper);
#endif
		if (i->SubList){
			if (IsInListTime(i->SubList, Number, Now)) return TRUE;
		}else if ( (i->Lower<=Number) && (i->Upper>=Number) ){
			return TRUE;
		}	
	}
	
	return FALSE;
}


/****************************************************
* Given an alias list, replace with numbers
****************************************************/
int ReplaceAliases(char* s1, int s1len, char* s2, int s2len, NumAlias* a, int NumAliases){
	int		i;
	char	TempBuff[65536];
	char*	pos;
	
	DEBUGPATH;

	if (s1len>65536) return FALSE;
	if (NumAliases==0){
		snprintf(s2, s2len, "%s", s1);
		return TRUE;
	}

	snprintf(TempBuff, 65535, "%s",s1);

	for (i=0;i<NumAliases;i++){
		pos=TempBuff;
		while ( (pos=strstr(pos, a[i].Alias)) ){
			memcpy(TempBuff, TempBuff, pos-TempBuff);
			TempBuff[pos-TempBuff]=0;
			sprintf(TempBuff+strlen(TempBuff),"%u",a[i].Num);
			sprintf(TempBuff+strlen(TempBuff), "%s", pos+strlen(a[i].Alias));
			pos=TempBuff;
		}
	}
	
	snprintf(s2, s2len, "%s", TempBuff);
	return TRUE;
}

/****************************************************
* Parse a string for the ranges
****************************************************/
int AddRangesString(NumList* n, char* RawRanges, NumAlias* Aliases, int NumAliases){
	int				i;
	char			ThisNum[64];
	int				ThisNumCount;
	unsigned int	LowNum;
	unsigned int	HighNum;
	int				IsRange;
	char*			Ranges;
	
	DEBUGPATH;

	if (!n) return FALSE;

	Ranges=calloc(strlen(RawRanges)*2,sizeof(char));
	if (!ReplaceAliases(RawRanges, strlen(RawRanges), Ranges, strlen(RawRanges)*2, Aliases, NumAliases)){
		printf("Couldn't apply alias list\n");
		free(Ranges);
		return FALSE;	
	}

	ThisNumCount=0;
	IsRange=FALSE;
	for (i=0;i<strlen(Ranges);i++){
		switch(Ranges[i]){
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			/*normal number, keep going*/
			ThisNum[ThisNumCount]=Ranges[i];
			ThisNumCount++;
			break;
		case ',':
			/*this a delimiter, add the numbers*/
			ThisNum[ThisNumCount]=0x00;
			if (!IsRange){
				LowNum=strtoul(ThisNum,NULL,10);
				AddRange(n, LowNum, LowNum);
#ifdef DEBUG
				printf("2Added Number %u-%u\n",LowNum, LowNum);
#endif				
			}else{
				HighNum=strtoul(ThisNum, NULL, 10);
				AddRange(n, LowNum, HighNum);
#ifdef DEBUG
				printf("Added Range %u-%u\n",LowNum, HighNum);
#endif								
			}
			ThisNumCount=0;
			IsRange=FALSE;
			break;
		case ' ':
			/*ignore white space*/
			break;
		case '-':
			/*this is a range*/
			ThisNum[ThisNumCount]=0x00;
			LowNum=strtoul(ThisNum, NULL, 10);
#ifdef DEBUG
			printf("Low part of the range is %u\n",LowNum);
#endif			
			IsRange=TRUE;
			ThisNumCount=0;
			break;
		default:
			printf("Invalid character \"%c\"\n", Ranges[i]);
			printf("I don't understand %s\n",Ranges);
			free(Ranges);
			return FALSE;
		}
	}

	/*Finish out the last one*/
	ThisNum[ThisNumCount]=0x00;
	if (!IsRange){
		LowNum=strtoul(ThisNum,NULL,10);
		AddRange(n, LowNum, LowNum);
#ifdef DEBUG
		printf("3Added Number %u-%u\n",LowNum, LowNum);
#endif				
	}else{
		HighNum=strtoul(ThisNum, NULL, 10);
		AddRange(n, LowNum, HighNum);
#ifdef DEBUG
		printf("Added Range %u-%u\n",LowNum, HighNum);
#endif								
	}

	free(Ranges);
	return TRUE;
}

/*******************************************************
* Convert an IP list to numbers and add them
********************************************************/
int AddIPRanges(NumList* n, char* Ranges){
	int				i;
	char			ThisNum[64];
	int				ThisNumCount;
	unsigned int	LowNum;
	unsigned int	HighNum;
	unsigned int	Mask;
	int				SubListID;
	int				IsDashed=FALSE;
	
	DEBUGPATH;

	if (!n) return FALSE;

#ifdef DEBUG
	printf("Ranges is %s\n",Ranges);
#endif	

	if ( (SubListID=GetListByName(Ranges))!=LIST_NONE){
		if (!AddSubList(n,Globals.Lists[SubListID].List)){
			printf("Failed to add ip list \"%s\" \n",Ranges);
			return FALSE;
		}
		return TRUE;
	}
	
	ThisNumCount=0;
	LowNum=0;
	for (i=0;i<=strlen(Ranges);i++){
		switch(Ranges[i]){
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
		case '.':
			/*normal number, keep going*/
			ThisNum[ThisNumCount]=Ranges[i];
			ThisNumCount++;
			break;
		case '-':
			/*contiguous range notation*/
			/*this a delimiter, add the numbers*/
			ThisNum[ThisNumCount]=0x00;
			LowNum=ntohl(inet_addr(ThisNum));
#ifdef DEBUG
			printf("Setting Low Range to %u\n",LowNum);
#endif				
			ThisNumCount=0;
			IsDashed=TRUE;
			break;			
		case 0x00:
		case ',':
			/*this a delimiter, add the numbers*/
			ThisNum[ThisNumCount]=0x00;
			HighNum=ntohl(inet_addr(ThisNum));
			if (LowNum==0) LowNum=HighNum;
			if (IsDashed){
				AddRange(n, LowNum, HighNum);
#ifdef DEBUG
				printf("1Added Number %u-%u\n",LowNum, HighNum);
#endif										
			}else{
				/*there may be a bug here*/
				/*keep an eye on it*/
				AddRange(n, LowNum, LowNum);
#ifdef DEBUG
				printf("5Added Number %u-%u\n", LowNum, LowNum);
#endif				
			}
			ThisNumCount=0;
			IsDashed=FALSE;
			LowNum=0;
			break;
		case ' ':
			/*ignore white space*/
			break;
		case '/':
			/*this is a range*/
			ThisNum[ThisNumCount]=0x00;
			LowNum=ntohl(inet_addr(ThisNum));
			i++;
			Mask=atoi(&Ranges[i]);
			HighNum=LowNum;
			switch (Mask){
			case 0:
				LowNum&=0x00000000;
				HighNum|=0xFFFFFFFF;
				AddRange(n, LowNum, HighNum);
				break;			
			case 1:
				LowNum&=0x10000000;
				HighNum|=0x7FFFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 2:
				LowNum&=0x30000000;
				HighNum|=0x3FFFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 3:
				LowNum&=0x70000000;
				HighNum|=0x1FFFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 4:
				LowNum&=0xF0000000;
				HighNum|=0x0FFFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 5:
				LowNum&=0xF1000000;
				HighNum|=0x07FFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 6:
				LowNum&=0xF3000000;
				HighNum|=0x03FFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 7:
				LowNum&=0xF7000000;
				HighNum|=0x01FFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 8:
				LowNum&=0xFF000000;
				HighNum|=0x00FFFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 9:
				LowNum&=0xFF100000;
				HighNum|=0x007FFFFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 10:
				LowNum&=0xFF300000;
				HighNum|=0x003FFFFF;
				AddRange(n, LowNum, HighNum);
				break;									
			case 11:
				LowNum&=0xFF700000;
				HighNum|=0x001FFFFF;
				AddRange(n, LowNum, HighNum);
				break;									
			case 12:
				LowNum&=0xFFF00000;
				HighNum|=0x000FFFFF;
				AddRange(n, LowNum, HighNum);
				break;									
			case 13:
				LowNum&=0xFFF10000;
				HighNum|=0x0007FFFF;
				AddRange(n, LowNum, HighNum);
				break;									
			case 14:
				LowNum&=0xFFF30000;
				HighNum|=0x0003FFFF;
				AddRange(n, LowNum, HighNum);
				break;									
			case 15:
				LowNum&=0xFFF70000;
				HighNum|=0x0001FFFF;
				AddRange(n, LowNum, HighNum);
				break;									
			case 16:
				LowNum&=0xFFFF0000;
				HighNum|=0x0000FFFF;
				AddRange(n, LowNum, HighNum);
				break;
			case 17:
				LowNum&=0xFFFF1000;
				HighNum|=0x00007FFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 18:
				LowNum&=0xFFFF3000;
				HighNum|=0x00003FFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 19:
				LowNum&=0xFFFF7000;
				HighNum|=0x00001FFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 20:
				LowNum&=0xFFFF000;
				HighNum|=0x00000FFF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 21:
				LowNum&=0xFFFFF100;
				HighNum|=0x000007FF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 22:
				LowNum&=0xFFFFF300;
				HighNum|=0x000003FF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 23:
				LowNum&=0xFFFFF700;
				HighNum|=0x000001FF;
				AddRange(n, LowNum, HighNum);
				break;						
			case 24:
				LowNum&=0xFFFFFF00;
				HighNum|=0x000000FF;
				AddRange(n, LowNum, HighNum);
				break;			
			case 25:
				LowNum&=0xFFFFFF10;
				HighNum|=0x0000007F;
				AddRange(n, LowNum, HighNum);
				break;						
			case 26:
				LowNum&=0xFFFFFF30;
				HighNum|=0x0000003F;
				AddRange(n, LowNum, HighNum);
				break;						
			case 27:
				LowNum&=0xFFFFFF70;
				HighNum|=0x0000001F;
				AddRange(n, LowNum, HighNum);
				break;						
			case 28:
				LowNum&=0xFFFFFFF0;
				HighNum|=0x0000000F;
				AddRange(n, LowNum, HighNum);
				break;						
			case 29:
				LowNum&=0xFFFFFFF1;
				HighNum|=0x00000007;
				AddRange(n, LowNum, HighNum);
				break;						
			case 30:
				LowNum&=0xFFFFFFF3;
				HighNum|=0x00000003;
				AddRange(n, LowNum, HighNum);
				break;						
			case 31:
				LowNum&=0xFFFFFFF7;
				HighNum|=0x00000001;
				AddRange(n, LowNum, HighNum);
				break;			
			case 32:
				LowNum&=0xFFFFFFFF;
				HighNum|=0x00000000;
				AddRange(n, LowNum, HighNum);
				break;
			default:
				printf("Invalid CIDR Notation /%u\n",Mask);
				return FALSE;
			}
			
#ifdef DEBUG
			printf("1Added Range %u-%u\n",LowNum, HighNum);
#endif				

			
			while ((Ranges[i]>='0') && (Ranges[i]<='9')) i++;
			ThisNumCount=0;
			IsDashed=FALSE;
			
			break;
		default:
			printf("Invalid character \"%c\"\n", Ranges[i]);
			printf("I don't understand %s\n",Ranges);
			return FALSE;
		}
	}

	return TRUE;
}

/*************************************
* Remove the first range that matches
*************************************/
int	RemoveFromList(NumList* n, unsigned int Number){
	NumItem*	i;
	int			j;
	
	DEBUGPATH;

	if (!n->NumEntries) return FALSE;
	
	for (j=0;j<n->NumEntries;j++){
		i=n->Items[j];
#ifdef DEBUG	
		printf("Checking for %u in %u-%u\n",Number, i->Lower, i->Upper);
#endif
		if (i->SubList){
			if (RemoveFromList(i->SubList, Number)) return TRUE;
		}else if ( (i->Lower<=Number) && (i->Upper>=Number) ){
			free(n->Items[j]);
			n->Items[j]=NULL;
			memmove(&n->Items[j], &n->Items[j+1], sizeof(NumItem*)*(n->NumEntries-j));
			n->Items[n->NumEntries]=NULL;
			n->NumEntries--;
			return TRUE;
		}	
	}
	
	return FALSE;
}

/***********************************************
* Return TRUE if the two num_lists are 
* identical
***********************************************/
int NumListCompare(NumList* n1, NumList* n2){
	NumItem*	t1;
	NumItem*	t2;
	int			i;
	
	DEBUGPATH;

	if (n1->NumEntries != n2->NumEntries){
#ifdef DEBUG
		printf("Two lists don't have same number of entries\n");
#endif	
		return FALSE;
	}

	for (i=0;i<n1->NumEntries;i++){
		t1=n1->Items[i];
		t2=n2->Items[i];

		if (
			(t1->SubList != t2->SubList) ||
			(t1->Lower   != t2->Lower) ||
			(t1->Upper   != t2->Upper)
		){
#ifdef DEBUG
			printf("They don't match\n");
#endif		
			return FALSE;
		}
	}

	return TRUE;
}
