/****************************************
* Sample module to demonstrate some of
* the covert channel detection mechanisms
*
* 1) Northcut's stimulus/response
* 2) CounterPane's Length
* 3) Anonpoet's Time
* 4) Drink or Die's content
*
* Probably not all that useful on a real
* network.  May make into a functioning
* module later.
*
* Currently hard coded to look at only
* ICMP traffic
*****************************************/
#include "module_covert.h"
#include <stdio.h>
#include "../decoders/decode_ip.h"
#include "../decoders/decode_icmp.h"

//#define DEBUG

int					IPDecoderID;
int					ICMPDecoderID;
extern GlobalVars	Globals;

#define PACKET_WINDOW				20
#define MAX_COVERT_SESSIONS			128
#define COVERT_SESSION_TIMEOUT		60

typedef struct covert_packet{
	unsigned int	SourceIP;
	int				Len;
	int				TimeStamp;
	int				TimeUSec;
	unsigned char	Content[256];
} CovertPacket;

typedef struct covert_session{
	int				InUse;
	unsigned int	IP1;
	unsigned int	IP2;
	int				PacketCount;
	int				LastTime;
	
	CovertPacket	Packets[PACKET_WINDOW];
} CovertSession;

CovertSession	CSessions[MAX_COVERT_SESSIONS];

/*******************************************
* Set some values on the module
*******************************************/
int CovertParseArg (char* Arg){
#ifdef DEBUGPATH
	printf("In CovertParseArg\n");
#endif

	return TRUE;
}

/****************************************
* assign to a session so we can do
* statistics on the session
****************************************/
int AssignSession(unsigned int SIP, unsigned int DIP, int Now){
	int		i;
	int		j;
	
	for (i=0;i<MAX_COVERT_SESSIONS;i++){
		if (CSessions[i].InUse){
			if ( (CSessions[i].IP1==SIP) && (CSessions[i].IP2==DIP) ){
#ifdef DEBUG
				printf("Found session %i\n",i);
#endif			
				CSessions[i].LastTime=Now;
				return i;
			}
			if ( (CSessions[i].IP2==SIP) && (CSessions[i].IP1==DIP) ){
#ifdef DEBUG
				printf("Found session %i\n",i);
#endif			
				CSessions[i].LastTime=Now;
				return i;
			}		
		}
	}

	for (i=0;i<MAX_COVERT_SESSIONS;i++){
		if ((CSessions[i].LastTime+COVERT_SESSION_TIMEOUT)<Now){
#ifdef DEBUG
			printf("Timing out session %i\n",i);
#endif		
			CSessions[i].InUse=FALSE;
		}
	
		if (!CSessions[i].InUse){
			bzero(&CSessions[i], sizeof(CovertSession));
			CSessions[i].InUse=TRUE;
			CSessions[i].IP1=SIP;
			CSessions[i].IP2=DIP;
			CSessions[i].LastTime=Now;
#ifdef DEBUG
			printf("Created session %i\n",i);
#endif			
			return i;
		}
	}
	
#ifdef DEBUG
	printf("All sessions are in use\n");
#endif	
	
	return -1;
}


/***************************************
* Check to see if the Content Check
* is triggered
***************************************/
void DetectContent(CovertSession* cs){
	double	max;
	int		count;
	int		i;

#ifdef DEBUG
	printf("Detecting Content\n");
#endif

	/*go find the max*/
	max=0;
	for (i=0;i<256;i++){
		count=cs->Packets[cs->PacketCount-1].Content[i];
		if (count>max) max=count;
	}
	
	/*again hard coded ratios for ping packets*/
#ifdef DEBUG	
	printf("max is %f\n",max);
#endif	
	
	if (max>6){
		printf("Drink or Die's content check\n");
		printf("  %s<>",inet_ntoa(cs->IP1));
		printf("  %s\n",inet_ntoa(cs->IP2));		
	}
}


/***************************************
* Check to see if the Time Check
* is triggered
***************************************/
void DetectTime(CovertSession* cs){
	double	ShortCount=0;
	double	SecondCount=0;
	double	TwoSecondCount=0;
	double	LongCount=0;
	int		i;

#ifdef DEBUG
	printf("Detecting Times\n");
#endif

	/*we need at least 6 packets to have a chance*/
	if (cs->PacketCount<6) return;

	for (i=0;i<cs->PacketCount-1;i++){
		if (cs->Packets[i].TimeStamp==cs->Packets[i+1].TimeStamp){
			ShortCount++;
		}else if ((cs->Packets[i+1].TimeStamp-cs->Packets[i].TimeStamp)==1){
			SecondCount++;
		}else if ((cs->Packets[i+1].TimeStamp-cs->Packets[i].TimeStamp)==2){
			TwoSecondCount++;
		}else{
			LongCount++;
		}	
	}
	
#ifdef DEBUG
	printf("Short %f Second %f Two %f Long %f\n",ShortCount, SecondCount, TwoSecondCount, LongCount);
#endif	

	/*again hard coded ratios for ping packets*/
	if (ShortCount>(SecondCount+3)){
		printf("Anonpoet's Time Detect\n");
		printf("  %s<>",inet_ntoa(cs->IP1));
		printf("  %s\n",inet_ntoa(cs->IP2));
	}
	
	if (TwoSecondCount>6){
		printf("Anonpoet's Time Detect\n");
		printf("  %s<>",inet_ntoa(cs->IP1));
		printf("  %s\n",inet_ntoa(cs->IP2));		
	}
	
	if (LongCount>4){
		printf("Anonpoet's Time Detect\n");
		printf("  %s<>",inet_ntoa(cs->IP1));
		printf("  %s\n",inet_ntoa(cs->IP2));		
	}
}


/***************************************
* Check to see if the Length Check
* is triggered
***************************************/
void DetectLengths(CovertSession* cs){
	double	ShortCount=0;
	double	MediumCount=0;
	double	LongCount=0;
	double 	Ratio;
	int		i;

#ifdef DEBUG
	printf("Detecting Lengths\n");
#endif

	/*we need at least 6 packets to have a chance*/
	if (cs->PacketCount<6) return;

	for (i=0;i<cs->PacketCount;i++){
		if (cs->Packets[i].Len < 20){
			ShortCount++;
		}else if (cs->Packets[i].Len <500){
			MediumCount++;
		}else{
			LongCount++;
		}
	}
	
#ifdef DEBUG
	printf("Short %f Meduim %f Long %f\n",ShortCount, MediumCount, LongCount);
#endif	

	/*again hard coded ratios for ping packets*/
	Ratio=ShortCount/MediumCount;
	if ( (Ratio>.2) && (Ratio<5) && (ShortCount>3) ){
		printf("Counterpane Lengths Detect\n");
		printf("  %s<>",inet_ntoa(cs->IP1));
		printf("  %s\n",inet_ntoa(cs->IP2));		
	}
}

/***************************************
* Check to see if the Stimulus Response
* is triggered
***************************************/
void DetectStimulusResponse(CovertSession* cs){
	int		i;
	double	IP1Count;
	double	IP2Count;
	double 	Ratio;
	
#ifdef DEBUG
	printf("Detecting StimulusResponse\n");
#endif

	/*we need at least 6 packets to have a chance*/
	if (cs->PacketCount<6) return;

	IP1Count=0.0;
	IP2Count=0.0;
	for (i=0;i<cs->PacketCount;i++){
		if (cs->Packets[i].SourceIP==cs->IP1){
			IP1Count=IP1Count+1.0;
		}else{
			IP2Count=IP2Count+1.0;
		}
	}

	Ratio=IP1Count/IP2Count;
#ifdef DEBUG
	printf("There are %f IP1 and %f IP2 for a ratio of %f\n",IP1Count, IP2Count, IP1Count/IP2Count);
#endif	

	/*the ratio for ping traffic should approach 1:1*/
	if ( (Ratio>1.5) || (Ratio<.5) ){
		printf("Northcut Stimulus/Response Detect\n");
		printf("  %s<>",inet_ntoa(cs->IP1));
		printf("  %s\n",inet_ntoa(cs->IP2));
	}
	
}

/***************************************
* look for covert channels
***************************************/
void CovertFunc(int PacketSlot){
	IPData*			IPData;
	ICMPData*		ICMPData;
	PacketRec*		p;
	int				SessionID;
	CovertPacket*	cp;
	int				i;
	
#ifdef DEBUGPATH
	printf("In CovertFunc\n");
#endif	

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IPData)){
#ifdef DEBUG
		printf("Couldn't get IP Header\n");
#endif	
		return;
	}

	if (!GetDataByID(PacketSlot, ICMPDecoderID, (void**)&ICMPData)){
#ifdef DEBUG
		printf("Couldn't get ICMP Header\n");
#endif	
		return;
	}
	
#ifdef DEBUG	
	printf("Covert: This is an ICMP packet\n");
	printf("%s->",inet_ntoa(IPData->Header->saddr));
	printf("%s\n",inet_ntoa(IPData->Header->daddr));
#endif

	SessionID=AssignSession(IPData->Header->saddr, IPData->Header->daddr, p->tv.tv_sec);
	if (SessionID==-1){
#ifdef DEBUG
		printf("Failed to assign a session\n");
#endif
		return;	
	}

	/*move packets down if queue is full*/
	if (CSessions[SessionID].PacketCount==PACKET_WINDOW-1){
#ifdef DEBUG
		printf("Window is full.  Making more room\n");
#endif	
		memmove(&CSessions[SessionID].Packets[0],
			&CSessions[SessionID].Packets[1],
			sizeof(CovertPacket)*(PACKET_WINDOW-1)
		);
		
		CSessions[SessionID].PacketCount--;
	}

	/*Fill in the packet data*/
	cp=&CSessions[SessionID].Packets[CSessions[SessionID].PacketCount];
	cp->SourceIP=IPData->Header->saddr;
	cp->Len=p->PacketLen-p->BeginData;
	cp->TimeStamp=p->tv.tv_sec;
	cp->TimeUSec=p->tv.tv_usec;
	for (i=p->BeginData;i<p->PacketLen;i++){
		cp->Content[p->RawPacket[i]]++;
	}
	
	CSessions[SessionID].PacketCount++;
	
	DetectStimulusResponse(&CSessions[SessionID]);
	DetectLengths(&CSessions[SessionID]);
	DetectTime(&CSessions[SessionID]);
	DetectContent(&CSessions[SessionID]);
}

/**************************************
* Set up the covert channel logger
**************************************/
int InitModuleCovert(){
	int	ModuleID;
	
#ifdef DEBUGPATH
	printf("In InitModuleCovert\n");
#endif

	bzero(CSessions, sizeof(CovertSession)*MAX_COVERT_SESSIONS);

	ModuleID=CreateModule("covert");
	if(ModuleID==MODULE_NONE) return FALSE;
	
	if (!BindModuleToDecoder(ModuleID, "ICMP")){
		printf("Failed to bind Covert Module to ICMP\n");
		return FALSE;
	}
	
	Globals.Modules[ModuleID].ParseArg=CovertParseArg;
	Globals.Modules[ModuleID].ModuleFunc=CovertFunc;

	IPDecoderID=GetDecoderByName("IP");
	ICMPDecoderID=GetDecoderByName("ICMP");

	Globals.Decoders[GetDecoderByName("IP")].Active=TRUE;
	Globals.Decoders[GetDecoderByName("ICMP")].Active=TRUE;
	
	return TRUE;
}


