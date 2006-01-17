#include "mangle.h"
#include "mangle_hard_mac.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

extern GlobalVars Globals;

//#define DEBUG

/**************************************
* Set up all the manglers
**************************************/
int InitManglers(){
#ifdef DEBUGPATH
	printf("in InitManglers\n");
#endif

	if (!InitMangleHardMac()) return FALSE;

	return TRUE;
}

/********************************
* Create a new mangler
*********************************/
int CreateMangler(char* Name){
	int MangleID;
	
#ifdef DEBUGPATH
	printf("In CreateMangler\n");
#endif

	/*check to see if this name is already used*/
	MangleID=GetManglerByName(Name);
	if (MangleID!=MANGLE_NONE){
		printf("Mangler %s already exists\n",Name);
		return MANGLE_NONE;
	}
	
	MangleID=Globals.NumMangles;
	Globals.NumMangles++;
	
	bzero(&Globals.Mangles[MangleID], sizeof(MangleRec));
	Globals.Mangles[MangleID].ID=MangleID;
	snprintf(Globals.Mangles[MangleID].Name, MAX_NAME_LEN, Name);
	
#ifdef DEBUG
	printf("Allocated Mangler \"%s\" at number %i\n",Name, MangleID);
#endif	
	
	return MangleID;
}

/***********************************
* Given an route's name, return
* its ID
***********************************/
int GetManglerByName(char* Name){
	int	i;

#ifdef DEBUGPATH
	printf("GetMangleByName\n");
#endif

	for (i=0;i<Globals.NumMangles;i++){
		if (strcasecmp(Name, Globals.Mangles[i].Name)==0){
			return i;
		}
	}

	return MANGLE_NONE;
}

/********************************************
* instance a mangler
********************************************/
int ManglerAdd(int MangleID, char* Args){
#ifdef DEBUGPATH
	printf("In ManglerAdd\n");
#endif

	if (MangleID>=Globals.NumMangles) return FALSE;
	if (!Globals.Mangles[MangleID].AddNode) return FALSE;
	
	return Globals.Mangles[MangleID].AddNode(MangleID, Args);
}

/************************************
* Slice and dice the packet
*************************************/
int Mangle(int PacketSlot, int SourceInterface, int TargetInterface){
	int 		i;
	
#ifdef DEBUGPATH
	printf("In Mangle\n");
#endif	

	for (i=0;i<Globals.NumMangles;i++){
		if (Globals.Mangles[i].Active)
		if (Globals.Mangles[i].MangleFunc){
			Globals.Mangles[i].MangleFunc(PacketSlot, SourceInterface, TargetInterface);
		}
	}

	return TRUE;	
}
