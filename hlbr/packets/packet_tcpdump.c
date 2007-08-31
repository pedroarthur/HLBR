#include "packet_tcpdump.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

/*struct out of libpcap*/
struct dump_pcap_pkthdr {
	struct 			timeval ts;	/* time stamp */
	unsigned int 	caplen;	/* length of portion present */
	unsigned int	len;	/* length this packet (off wire) */
};

#define DUMP_PCAP_VERSION_MAJOR 2
#define DUMP_PCAP_VERSION_MINOR 4

/*struct out of libpcap*/
struct dump_pcap_file_header {
	unsigned int	magic;
	unsigned short	version_major;
	unsigned short	version_minor;
	int				thiszone;	/* gmt to local correction */
	unsigned int	sigfigs;	/* accuracy of timestamps */
	unsigned int	snaplen;	/* max length saved portion of each pkt */
	unsigned int	linktype;	/* data link type (LINKTYPE_*) */
};


//#define DEBUG

extern GlobalVars	Globals;

/*********************************************
* Open an interface to read from a tcpdump file
**********************************************/
int OpenInterfaceTCPDump(int InterfaceID){
	int						fd;
	InterfaceRec*			Interface;
	struct dump_pcap_file_header	Header;

#ifdef DEBUGPATH
	printf("In OpenInterfaceTCPDump\n");
#endif


	Interface=&Globals.Interfaces[InterfaceID];

#ifdef DEBUG
	printf("Opening tcpdump file %s\n", Interface->Name);
#endif

	fd=open(Interface->Name, O_RDONLY);
	if (fd==-1){
		printf("Failed to open \"%s\" for reading\n",Interface->Name);
		return FALSE;
	}

	if (read(fd, &Header, sizeof(Header))!=	sizeof(Header)){
		printf("Failed to read TCPDump Header from \"%s\"\n",Interface->Name);
		return FALSE;
	}
	
	if (Header.magic != htonl(0xd4c3b2a1)){
		printf("Header magic number didn't match. Not a TCPDUMP file?\n");
		return FALSE;
	}	

	Interface->FD=fd;
	Interface->MTU=Header.snaplen;
	Interface->IsPollable=TRUE;
	
	return TRUE;
}

/**********************************************
* Read a packet off of a tcpdump file
**********************************************/
int ReadPacketTCPDump(int InterfaceID){
	int 			count;
	InterfaceRec*	Interface;
	int				PacketSlot;
	PacketRec*		p;
	struct dump_pcap_pkthdr	Header;
	
#ifdef DEBUGPATH
	printf("In ReadPacketTCPDump\n");
#endif

#ifdef DEBUG
	printf("Reading packet from tcpdump file\n");
#endif

	Interface=&Globals.Interfaces[InterfaceID];
	if ( (PacketSlot=GetEmptyPacket())==-1){
		printf("Unable to allocate packet for reading\n");
		return FALSE;		
	}	
	
	p=&Globals.Packets[PacketSlot];
	
	p->InterfaceNum=InterfaceID;

	/*read in the packet header*/
	count = read(Interface->FD, (char*)&Header, sizeof(Header));
	if (count!=sizeof(Header)){
#ifdef DEBUG	
		printf("Failed to read packet header\n");
#endif		
		ReturnEmptyPacket(PacketSlot);
		/*exit when you get to the end of a tcpdump file*/
		Globals.Done=TRUE;
	}

	/*read in the packet*/
	count = read(Interface->FD, (char*)p->RawPacket, Header.caplen);
	if (count==-1){
#ifdef DEBUG	
		printf("Failed to read packet.\n");
#endif		
		ReturnEmptyPacket(PacketSlot);
		/*exit when you get to the end of a tcpdump file*/
		exit(0);
	}
	p->PacketLen=count;
	p->tv=Header.ts;	

	if (!AddPacketToPending(PacketSlot)){
		printf("Coulnd't add packet to pending queue\n");
		ReturnEmptyPacket(PacketSlot);
		return FALSE;
	}

	return TRUE;
}

/***************************************************
* Send a packet off to the raw interface
****************************************************/
int WritePacketTCPDump(int InterfaceID, unsigned char* Packet, int PacketLen){	
#ifdef DEBUGPATH
	printf("In WritePacketTCPDumpRaw\n");
#endif
	
	return FALSE;
}

/**********************************************
* The thread func
**********************************************/
void* TCPDumpLoopFunc(void* v){
	int				InterfaceID;

#ifdef DEBUGPATH
	printf("In TCPDumpRawLoopFunc\n");
#endif

	InterfaceID=(int)v;
	while (!Globals.Done){
		ReadPacketTCPDump(InterfaceID);
	}
	
	return NULL;
}

/**********************************************
* Start a thread to continuously read
**********************************************/
int LoopThreadTCPDump(int InterfaceID){
#ifdef DEBUGPATH
	printf("In loopThreadTCPDumpRaw\n");
#endif

#ifndef HAS_THREADS
	return FALSE;
#else

#ifdef DEBUG
	printf("Starting Thread for interface %s\n",Globals.Interfaces[InterfaceID].Name);
#endif

	Globals.Interfaces[InterfaceID].ThreadID=pthread_create(
		&Globals.Interfaces[InterfaceID].Thread,
		NULL,
		TCPDumpLoopFunc,
		(void*)InterfaceID
	);
	
	return (!Globals.Interfaces[InterfaceID].ThreadID);
#endif
	
}

