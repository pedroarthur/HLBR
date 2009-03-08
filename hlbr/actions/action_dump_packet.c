#include "action_dump_packet.h"
#include <stdio.h>
#include "../engine/message.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/stat.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

//#define DEBUG

/*struct out of libpcap to output to tcpdump format*/
struct dump_pcap_pkthdr {
	struct 			timeval ts;	/* time stamp */
	unsigned int 	caplen;	/* length of portion present */
	unsigned int	len;	/* length this packet (off wire) */
};

#define DUMP_PCAP_VERSION_MAJOR 2
#define DUMP_PCAP_VERSION_MINOR 4

/*struct out of libpcap to output to tcpdump format*/
struct dump_pcap_file_header {
	unsigned int	magic;
	unsigned short	version_major;
	unsigned short	version_minor;
	int				thiszone;	/* gmt to local correction */
	unsigned int	sigfigs;	/* accuracy of timestamps */
	unsigned int	snaplen;	/* max length saved portion of each pkt */
	unsigned int	linktype;	/* data link type (LINKTYPE_*) */
};



typedef struct dump_packet_rec{
	char		fname[1024];
#ifdef MTHREADS
	pthread_mutex_t	DumpMutex;
	int		DumpLockID;
#endif
} DumpPacketRec;

extern GlobalVars	Globals;

FILE*	fp;

/*****************************************
* Write out the TCPDump Header
*****************************************/
int InitTCPDumpFile(char* FName){
	struct dump_pcap_file_header	Header;
	FILE*							fp;

	DEBUGPATH;

	fp=fopen(FName, "w+");
	if (!fp){
		printf("Couldn't open \"%s\" for writing\n",FName);
		return FALSE;
	}

	bzero(&Header,sizeof(struct dump_pcap_file_header));
	Header.magic=htonl(0xd4c3b2a1);
	Header.version_major=DUMP_PCAP_VERSION_MAJOR;
	Header.version_minor=DUMP_PCAP_VERSION_MINOR;
	Header.snaplen=1600;
	Header.linktype=1;
	
#ifdef DEBUG
	printf("Writing out header\n");
#endif	

	fwrite(&Header, sizeof(struct dump_pcap_file_header), 1, fp);	
	fclose(fp);

	return TRUE;
}

/******************************************
* Parse the args for this action
******************************************/
void* DumpPacketParseArgs(char* Args){
	DumpPacketRec*	data;
	char			FileName[1024];
	struct stat		st;

	DEBUGPATH;

	snprintf(FileName,1024,"%s%s",Globals.LogDir, Args);
	data=(DumpPacketRec*)calloc(sizeof(DumpPacketRec),1);
	snprintf(data->fname, 1024, "%s", FileName);
	
	if (stat(FileName, &st)==-1){
#ifdef DEBUG
		printf("%s: File doesn't exist.  Creating\n", FileName);
#endif	
		if (!InitTCPDumpFile(FileName)){
			printf("Couldn't create packet dump \"%s\"\n",FileName);
			return NULL;
		}
	}
	
	return data;
}


/******************************************
* save this packet into the packet dump
******************************************/
int DumpPacketAction(int RuleNum, int PacketSlot, void* Data){
	FILE*				fp;
	DumpPacketRec*			data;
	PacketRec*			p;
	struct dump_pcap_pkthdr		Header;
#ifdef MTHREADS
	int				ocs;
#endif
	
	DEBUGPATH;

	if (!Data){
#ifdef DEBUG
		printf("I must have a filename to write to\n");
#endif	
		return FALSE;
	}
	
	
	p=&Globals.Packets[PacketSlot];
	data=(DumpPacketRec*)Data;

	Header.ts=p->tv;
	Header.caplen=p->PacketLen;
	Header.len=p->PacketLen;
#ifdef MTHREADS
	pthread_mutex_lock (&data->DumpMutex);
#endif
	fp=fopen(data->fname, "a");
	if (!fp){
#ifdef DEBUG	
		printf("Couldn't open \"%s\" for appending\n",data->fname);
#endif

#ifdef MTHREADS
		pthread_mutex_unlock (&data->DumpMutex);
#endif
		return FALSE;
	}

#ifdef MTHREADS
	pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &ocs);
#endif

	fwrite(&Header, sizeof(struct dump_pcap_pkthdr),1,fp);
	fwrite(p->RawPacket, p->PacketLen, 1, fp);

#ifdef MTHREADS
	pthread_setcancelstate (ocs, NULL);
#endif

	fclose(fp);
#ifdef MTHREADS
	pthread_mutex_unlock (&data->DumpMutex);
#endif

	return TRUE;
}

/********************************
* Set up the packet dump stuffg
********************************/
int InitActionDumpPacket(){
	int ActionID;

	DEBUGPATH;

	ActionID=CreateAction("dump packet");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action dump packet\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=DumpPacketAction;
	Globals.ActionItems[ActionID].ParseArgs=DumpPacketParseArgs;

	return TRUE;
}
