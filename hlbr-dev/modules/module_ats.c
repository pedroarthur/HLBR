/****************************************
* This module will eventually go away
* and be replaced by the session handler
*****************************************/
#include "module_ats.h"
#include <stdio.h>
#include "../decoders/decode.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include "../decoders/decode_icmp.h"
#include "../decoders/decode_udp.h"
#include "../engine/message.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

//#define DEBUG
//#define DEBUG1
//#define DEBUG2

int					IPDecoderID;
int					TCPDecoderID;
int					UDPDecoderID;
int					ICMPDecoderID;
int					ATSModuleID;
extern GlobalVars	Globals;

MessageItem*	ATSFName;
char			ATSFilename[1024];

typedef struct traffic_item{
	unsigned int	ID;
	unsigned short	Port1;
	unsigned short 	Port2;
	unsigned int	TCPCount1;
	unsigned int	TCPCount2;
	unsigned int	UDPCount1;
	unsigned int	UDPCount2;
	unsigned int	ICMPCount1;
	unsigned int	ICMPCount2;
	unsigned int	OtherCount1;
	unsigned int	OtherCount2;
	unsigned char	Direction;
	long			StartTime;
	long			LastTime;
} TItem;

typedef struct traffic_pair{
	unsigned int	IP1;
	unsigned int	IP2;
	unsigned short	NumItems;
	unsigned short	NumItemSlots;
	TItem*			Items;
} TPair;

typedef struct traffic_bin{
	unsigned short	NumPairs;
	unsigned short	NumPairSlots;
	TPair*			Pairs;
} TBin;

#define MAX_TRAFFIC_BINS	65536
/*stick these in the config when done*/
#define MIN_PAIRS				10
#define MIN_ITEMS				20
#define SESSION_TIMEOUT			120
#define MAX_EXPIRES_PER_PASS	10
#define ATS_LOG_ROTATE_INTERVAL	60*60

TBin*			TBins[MAX_TRAFFIC_BINS];
FILE*			ATSfp;
int				ATSExpireCounter;
int				ATSLastRotate;
unsigned int	ATSID;

/*******************************************
* Set some values on the module
*******************************************/
int ModuleATSParseArg (char* Arg){
#ifdef DEBUGPATH
	printf("In ModuleATSParseArg\n");
#endif

	if (strncmp(Arg, "filename=",9)==0){
		ATSFName=ParseMessageString(Arg+9);
		ApplyMessage(ATSFName, 0, ATSFilename, 1024);
		printf("Setting filename to %s\n", ATSFilename);
		ATSfp=fopen(ATSFilename, "a");
		if (!ATSfp){
			printf("Couldn't open %s for appending\n",ATSFilename);
			return FALSE;
		}
		return TRUE;
	}else{
		printf("ATS:Unknown Option %s\n",Arg);
		return FALSE;	
	}

	return TRUE;
}


/***************************************
* Write a log entry out to disk
* Logging in human readable form for now
***************************************/
int LogATS(TBin* bin, TPair* pair, TItem* item){
	struct tm*	tm;
#ifdef DEBUGPATH
	printf("In LogATS\n");
#endif

	fprintf(ATSfp, "%08i ",item->ID);
	tm=localtime(&item->StartTime);					
	fprintf(ATSfp, "%02i/%02i/%04i %02i:%02i:%02i",
		tm->tm_mon+1, 
		tm->tm_mday+1,
		tm->tm_year+1900,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec);
	tm=localtime(&item->LastTime);
	fprintf(ATSfp, "-%02i:%02i:%02i ",
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec);
	fprintf(ATSfp, "%s:%u", inet_ntoa(*(struct in_addr*)&pair->IP1), item->Port1);
	if (item->Direction){fprintf(ATSfp, "->");}else{fprintf(ATSfp, "<-");}
	fprintf(ATSfp, "%s:%u  -  ",inet_ntoa(*(struct in_addr*)&pair->IP2),item->Port2);
	fprintf(ATSfp,"T %u:%u U %u:%u I %u:%u O %u:%u\n",
		item->TCPCount1, 
		item->TCPCount2, 
		item->UDPCount1, 
		item->UDPCount2,						
		item->ICMPCount1, 
		item->ICMPCount2,						
		item->OtherCount1,
		item->OtherCount2						
	);
	
	return TRUE;
}

/***************************************
* Search a bin for any items that need
* to be expired and expire them
***************************************/
int ExpireBin(unsigned short hash, long now){
	TBin*	bin;
	TPair*	pair;
	TItem*	item;
	int		i,j;
	int		expires;
	
#ifdef DEBUGPATH
	printf("In ExpireBin\n");
#endif
	
	bin=TBins[hash];
	
	if (!bin) return TRUE;
		
	expires=0;	
		
	for (i=0;i<bin->NumPairs;i++){
		pair=&bin->Pairs[i];
		for (j=0;j<pair->NumItems;j++){
			item=&pair->Items[j];
			
			if ((item->LastTime+SESSION_TIMEOUT)<now){
#ifdef DEBUG2
				printf("We need to expire this one\n");
#endif			
				/*write out the log entry*/
				LogATS(bin, pair, item);
				
				/*remove the item from the pair list*/
				memmove(&pair->Items[j], &pair->Items[j+1], sizeof(TItem) * (pair->NumItems-j-1));
				bzero(&pair->Items[pair->NumItems-1], sizeof(TItem));
				pair->NumItems--;
				expires++;
				
				/*bail if we're spending too long here*/
				if (expires > MAX_EXPIRES_PER_PASS){
					ATSExpireCounter--;
					break;
				}
			}
		}
		
		/*check to see if the pair is empty*/
		if (pair->NumItems<1){
#ifdef DEBUG2
			printf("This pair is empty\n");
#endif		
			free(pair->Items);
			pair->Items=NULL;
		
			memmove(&bin->Pairs[i], &bin->Pairs[i+1], sizeof(TPair) * (bin->NumPairs-i-1));
			bzero(&bin->Pairs[bin->NumPairs-1], sizeof(TPair));
			bin->NumPairs--;
			
			/*bail if we're spending too long here*/
			if (expires > MAX_EXPIRES_PER_PASS) break;
		}		
	}
	
	/*check to see if the bin is empty*/
	if (bin->NumPairs<1){
#ifdef DEBUG2
		printf("This bin is empty\n");
#endif			
		free(bin->Pairs);
		bin->Pairs=NULL;
		
		free(TBins[hash]);
		TBins[hash]=NULL;
	}
	
	return TRUE;
}

/***************************************
* Find out what bin this goes in
***************************************/
unsigned short GetHash(unsigned int ip1, unsigned int ip2){
	unsigned short	hash;
	unsigned short	v1;
#ifdef DEBUGPATH
	printf("In GetHash\n");
#endif

	hash=ip1/65536;
	v1=(ip1 & 0x0000FFFF);
	hash ^= v1;
	v1=ip2/65536;
	hash ^= v1;
	v1=(ip2 & 0x0000FFFF);
	hash ^= v1;

	return hash;
}

/****************************************
* Check to see if we need to rotate the
* log file
****************************************/
void RotateLogFile(int now){
#ifdef DEBUGPATH
	printf("In RotateLogFile\n");
#endif

	if ((ATSLastRotate>0) && ((now-ATSLastRotate)<ATS_LOG_ROTATE_INTERVAL)) return;
	
//#ifdef DEBUG
	printf("Log needs to be rotated\n");
//#endif	

	ApplyMessage(ATSFName, 0, ATSFilename, 1024);	
	printf("Setting filename to %s\n", ATSFilename);
	fclose(ATSfp);
	ATSfp=fopen(ATSFilename, "a");
	if (!ATSfp){
		printf("Couldn't open %s for appending\n",ATSFilename);
		return;
	}
	ATSLastRotate=now;
}


/***************************************
* Keep track of session information
***************************************/
void ModuleATSFunc(int PacketSlot){
	IPData*			IData=NULL;	
	TCPData*		TData=NULL;
	UDPData*		UData=NULL;
	ICMPData*		CData=NULL;
	
	unsigned short	hash;	
	unsigned short	pairnum;
	unsigned short	itemnum;
	TBin*			bin;
	TPair*			pair;
	TItem*			item;
	
	int				i;
	unsigned int	IP1;
	unsigned int	IP2;
	unsigned short	Port1;
	unsigned short	Port2;
	
#ifdef DEBUGPATH
	printf("In ModuleATSFunc\n");
#endif	

	RotateLogFile(Globals.Packets[PacketSlot].tv.tv_sec);

	GetDataByID(PacketSlot, IPDecoderID, (void**)&IData);
	GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData);
	GetDataByID(PacketSlot, UDPDecoderID, (void**)&UData);
	GetDataByID(PacketSlot, UDPDecoderID, (void**)&CData);
	
	if (!IData){
#ifdef DEBUG
		printf("We only track IP traffic\n");
#endif	
		return;
	}

#ifdef DEBUG
	printf("%s->",inet_ntoa(*(struct in_addr*)&IData->Header->saddr));
	printf("%s\n",inet_ntoa(*(struct in_addr*)&IData->Header->daddr));
#endif

	/*extract data*/
	if (IData->Header->saddr<IData->Header->daddr){
		IP1=IData->Header->saddr;
		IP2=IData->Header->daddr;
		if (TData){
			Port1=ntohs(TData->Header->source);
			Port2=ntohs(TData->Header->dest);
		}else if (UData){
			Port1=ntohs(UData->Header->source);
			Port2=ntohs(UData->Header->dest);
		}
	}else{
		IP1=IData->Header->daddr;
		IP2=IData->Header->saddr;
		if (TData){
			Port1=ntohs(TData->Header->dest);
			Port2=ntohs(TData->Header->source);
		}else if (UData){
			Port1=ntohs(UData->Header->dest);
			Port2=ntohs(UData->Header->source);
		}
	}
	hash=GetHash(IP1, IP2);

#ifdef DEBUG
	printf("This packet goes in bin %u\n",hash);
#endif

	/*go find the pair that this goes in*/
	if (!TBins[hash]){
#ifdef DEBUG
		printf("This is the first entry in bin %u\n",hash);
#endif	
		TBins[hash]=(TBin*)calloc(sizeof(TBin),1);
		bin=TBins[hash];
	}else{
		bin=TBins[hash];
	}
	
	/*********************************/
	/*go find the ip pair in that bin*/
	/*********************************/
	if (bin->NumPairSlots==0){
#ifdef DEBUG
		printf("This is the first pair in this bin\n");
#endif	
		bin->Pairs=calloc(sizeof(TPair),MIN_PAIRS);
		bin->NumPairSlots=MIN_PAIRS;
		bin->NumPairs=1;
		pair=&bin->Pairs[0];
		pairnum=0;
		
		/*fill in the first one*/
		pair->IP1=IP1;
		pair->IP2=IP2;
	}else{
		for (i=0;i<bin->NumPairs;i++){
			if ( (bin->Pairs[i].IP1==IP1) && (bin->Pairs[i].IP2==IP2) ){
#ifdef DEBUG
				printf("Found pair hash %u slot %u\n",hash,i);
#endif			
				pairnum=i;
				pair=&bin->Pairs[i];
				break;
			}
		}
				
		if (i==bin->NumPairs){		
#ifdef DEBUG
			printf("New in hash %u slot %u\n", hash, bin->NumPairs);
#endif
			if (bin->NumPairs<bin->NumPairSlots){
				/*there's room for this pair in the currently allocated memory*/
				pair=&bin->Pairs[bin->NumPairs];
				pairnum=bin->NumPairs;
				bin->NumPairs++;
			}else{
#ifdef DEBUG1
				printf("Allocating more pairs\n");
#endif						
				pair=calloc(sizeof(TPair),bin->NumPairSlots+MIN_PAIRS);
				memcpy(pair, bin->Pairs, sizeof(TPair) * bin->NumPairSlots);
				free(bin->Pairs);
				bin->NumPairSlots+=MIN_PAIRS;
				bin->Pairs=pair;
				
				pair=&bin->Pairs[bin->NumPairs];
				pairnum=bin->NumPairs;
				bin->NumPairs++;
			}			
			pair->IP1=IP1;
			pair->IP2=IP2;
		}
	}

	/****************************/
	/*find the item in that pair*/
	/****************************/
	if (pair->NumItemSlots==0){
#ifdef DEBUG
		printf("This is the first session between these two hosts\n");
#endif	
		pair->Items=calloc(sizeof(TItem), MIN_ITEMS);
		pair->NumItemSlots=MIN_ITEMS;
		pair->NumItems=1;
		item=&pair->Items[0];
		itemnum=0;
		
		/*fill in the item*/
		item->Port1=Port1;
		item->Port2=Port2;
		item->Direction=(IP1==IData->Header->saddr);
		item->StartTime=Globals.Packets[PacketSlot].tv.tv_sec;
		item->ID=ATSID++;
		
#ifdef DEBUG1
		printf("%u.%u.%u %s:%u",hash, pairnum, itemnum, inet_ntoa(*(struct in_addr*)&IP1), Port1);
		if (item->Direction){
			printf("->");
		}else{
			printf("<-");
		}
		printf("%s:%u\n",inet_ntoa(*(struct in_addr*)&IP2),Port2);
#endif		
		
	}else{
		for (i=0;i<pair->NumItems;i++){
			if ( (pair->Items[i].Port1==Port1) && (pair->Items[i].Port2==Port2) ){
#ifdef DEBUG
				printf("Found item in slot %u\n",i);
#endif		
				item=&pair->Items[i];
				break;		
			}
		}
		
		if (i==pair->NumItems){
#ifdef DEBUG
			printf("New in item slot %u\n",pair->NumItems);
#endif			
			if (pair->NumItems<pair->NumItemSlots){
				/*there is room for this item in allocated memory*/
				item=&pair->Items[pair->NumItems];
				itemnum=pair->NumItems;
				pair->NumItems++;
			}else{
#ifdef DEBUG1
				printf("Allocating more Items\n");
#endif					
				item=calloc(sizeof(TItem), pair->NumItemSlots+MIN_ITEMS);
				memcpy(item, pair->Items, sizeof(TItem) * pair->NumItemSlots);
				free(pair->Items);
				pair->NumItemSlots+=MIN_ITEMS;
				pair->Items=item;
				
				item=&pair->Items[pair->NumItems];
				itemnum=pair->NumItems;
				pair->NumItems++;
			}
			item->Port1=Port1;
			item->Port2=Port2;
			item->Direction=(IP1==IData->Header->saddr);
			item->StartTime=Globals.Packets[PacketSlot].tv.tv_sec;
			item->ID=ATSID++;
			
#ifdef DEBUG1
		printf("%u.%u.%u %s:%u",hash, pairnum, itemnum, inet_ntoa(*(struct in_addr*)&IP1), Port1);
			if (item->Direction){
				printf("->");
			}else{
				printf("<-");
			}
			printf("%s:%u\n",inet_ntoa(*(struct in_addr*)&IP2),Port2);
#endif		
		}
	}
	
	/*update the statistics*/
	item->LastTime=Globals.Packets[PacketSlot].tv.tv_sec;
	if (IData->Header->saddr>IData->Header->daddr){
		if (TData){			item->TCPCount1++;
		}else if (UData){	item->UDPCount1++;
		}else if (IData){	item->ICMPCount1++;
		}else{				item->OtherCount1++;
		}
	}else{
		if (TData){			item->TCPCount2++;
		}else if (UData){	item->UDPCount2++;
		}else if (IData){	item->ICMPCount2++;
		}else{				item->OtherCount2++;
		}
	}

	/*check to see if this bin needs emptying*/
	ExpireBin(ATSExpireCounter++, Globals.Packets[PacketSlot].tv.tv_sec);
}

/**************************************
* Log everything when we shut down
**************************************/
int ATSShutdownFunc(void* Data){
	int		i,j,k;
	TBin*	bin;
	TPair*	pair;
	TItem*	item;
	
#ifdef DEBUGPATH
	printf("In ATSShutdownFunc\n");
#endif

	if (Globals.Modules[ATSModuleID].Active==FALSE){
#ifdef DEBUG	
		printf("ATS module isn't active\n");
#endif
		return TRUE;
	}

	printf("Flushing ATS data to disk.....");	
	for (i=0;i<65536;i++){
		if (TBins[i]){
			bin=TBins[i];
			for (j=0;j<TBins[i]->NumPairs;j++){
				pair=&TBins[i]->Pairs[j];
				for (k=0;k<pair->NumItems;k++){
					item=&pair->Items[k];
					LogATS(bin, pair, item);					
				}
			}
		}
	}
	
	if (ATSfp) fclose(ATSfp);
	
	printf("Done\n");

	return TRUE;
}

/**************************************
* Set up the ATS logger
**************************************/
int InitModuleATS(){
	int	ModuleID;
	
#ifdef DEBUGPATH
	printf("In InitModuleATS\n");
#endif

	bzero(TBins, sizeof(TBin*) * MAX_TRAFFIC_BINS);

	ModuleID=CreateModule("ATS");
	if(ModuleID==MODULE_NONE) return FALSE;
	
	if (!BindModuleToDecoder(ModuleID, "TCP")){
		printf("Failed to bind ATS Module to TCP\n");
		return FALSE;
	}	
	if (!BindModuleToDecoder(ModuleID, "UDP")){
		printf("Failed to bind ATS Module to UDP\n");
		return FALSE;
	}	
	Globals.Modules[ModuleID].ParseArg=ModuleATSParseArg;
	Globals.Modules[ModuleID].ModuleFunc=ModuleATSFunc;
	
	/*we need to log everything during shutdown*/
	ATSModuleID=ModuleID;
	AddShutdownHandler(ATSShutdownFunc, NULL);

	IPDecoderID=GetDecoderByName("IP");
	TCPDecoderID=GetDecoderByName("TCP");
	UDPDecoderID=GetDecoderByName("UDP");
	ICMPDecoderID=GetDecoderByName("ICMP");
	
	ATSLastRotate=0;
	ATSID=0;
	
	return TRUE;
}

