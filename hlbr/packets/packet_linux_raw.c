#include "packet_linux_raw.h"

#ifdef _LINUX_
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#define DEBUG

extern GlobalVars	Globals;

/*********************************************
* Get the MTU of interface named "name"
*********************************************/
int GetIfrMTU(char *name) {
    int fd;
    struct ifreq ifr;
    int retval;

    retval = -1;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if ( fd < 0) {
        printf("Couldn't create socket for MTU\n");
        return -1;
    }

    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
        retval = ifr.ifr_metric;
    else
        printf("ioctl(SIOCGIFMTU)");    
    close(fd);
	return retval;
}

/*********************************************
* Get the id of interface named "name"
* Needed to open the interface
*********************************************/
int get_device_id(int fd, char* name){
	struct ifreq	ifr;

	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));	
	if (ioctl(fd, SIOGIFINDEX, &ifr) == -1) return -1;
	return ifr.ifr_ifindex;	
}

/*********************************************
* Open an interface via Linux Raw Sockets
**********************************************/
int OpenInterfaceLinuxRaw(int InterfaceID){
#ifdef DEBUGPATH
	printf("In OpenInterfaceLinuxRaw\n");
#endif
	int 				fd;
	struct sockaddr_ll	sll;
	int					ssize;
	int					errnum;
	struct packet_mreq	mr;
	InterfaceRec*		Interface;


	Interface=&Globals.Interfaces[InterfaceID];

#ifdef DEBUG
	printf("Opening interface %s\n", Interface->Name);
#endif

	fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	bzero(&sll,sizeof(struct sockaddr_ll));
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex=get_device_id(fd, Interface->Name);
	sll.sll_protocol=htons(ETH_P_ALL);
	ssize=sizeof(struct sockaddr_ll);

	errnum=bind(fd, (struct sockaddr*)&sll, sizeof(sll));
	if (errnum==-1){
		printf("Error Binding socket\n");
		return FALSE;
	}
	
	/*set promisc mode*/
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex=get_device_id(fd, Interface->Name);
	mr.mr_type=PACKET_MR_PROMISC;
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr))==-1){
		printf("Failed to set promisc mode\n");
		return FALSE;
	}

	Interface->FD=fd;
	Interface->MTU=GetIfrMTU(Interface->Name);
	if (Interface->MTU==-1) Interface->MTU=1500;

	Interface->IsPollable=TRUE;
	
	return TRUE;
}

/**********************************************
* Read a packet off of a Linux Raw Socket
**********************************************/
int ReadPacketLinuxRaw(int InterfaceID){
	int 			count;
	InterfaceRec*	Interface;
	int				PacketSlot;
	PacketRec*		p;
#ifdef DEBUG	
	int				i;
#endif	
	
#ifdef DEBUGPATH
	printf("In ReadPacketLinuxRaw\n");
#endif

	Interface=&Globals.Interfaces[InterfaceID];
	if ( (PacketSlot=GetEmptyPacket())==-1){
		printf("Unable to allocate packet for reading\n");
#ifdef DEBUG		
		printf("Packets are in the following states:\n");
		for (i=0;i<MAX_PACKETS;i++){
			switch (Globals.Packets[i].Status){
			case PACKET_STATUS_IDLE:
				printf("%i: idle\n",i);
				break;
			case PACKET_STATUS_PENDING:
				printf("%i: pending\n",i);
				break;				
			case PACKET_STATUS_SAVED:
				printf("%i: saved\n",i);
				break;				
			case PACKET_STATUS_ALLOCATED:
				printf("%i: allocated\n",i);
				break;				
			case PACKET_STATUS_PROCESSING:
				printf("%i: processing\n",i);
				break;				
			default:
				printf("%i: unknown(%i)\n",i, Globals.Packets[i].Status);
			}
		}
#endif			
		return FALSE;		
	}	

	
	p=&Globals.Packets[PacketSlot];
	
	p->InterfaceNum=InterfaceID;

	count = read(Interface->FD, (char*)p->RawPacket, TYPICAL_PACKET_SIZE-1);
	if (count==-1){
#ifdef DEBUG	
		printf("Failed to read packet. FD %i\n", Interface->FD);
#endif		
		ReturnEmptyPacket(PacketSlot);
		return FALSE;
	}
	p->PacketLen=count;
	
	if (ioctl(Interface->FD, SIOCGSTAMP, &p->tv)==-1){
#ifdef DEBUG	
		printf("Failed to get timestamp\n");
#endif
		ReturnEmptyPacket(PacketSlot);
		return FALSE;
	}

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
int WritePacketLinuxRaw(int InterfaceID, unsigned char* Packet, int PacketLen){
	int count;
	InterfaceRec* interface;
	
#ifdef DEBUGPATH
	printf("In WritePacketLinuxRaw\n");
#endif

	interface=&Globals.Interfaces[InterfaceID];
	
	count=write(interface->FD, Packet, PacketLen);
	if (count==-1){
		printf("Failed to write packet to interface %s\n",interface->Name);
		return FALSE;
	}
	
	return TRUE;
}

/**********************************************
* The thread func
**********************************************/
void* LinuxRawLoopFunc(void* v){
	int				InterfaceID;

#ifdef DEBUGPATH
	printf("In LinuxRawLoopFunc\n");
#endif

	InterfaceID=(int)v;
	while (!Globals.Done){
		ReadPacketLinuxRaw(InterfaceID);
	}
	
	return NULL;
}

/**********************************************
* Start a thread to continuously read
**********************************************/
int LoopThreadLinuxRaw(int InterfaceID){
#ifdef DEBUGPATH
	printf("In loopThreadLinuxRaw\n");
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
		LinuxRawLoopFunc,
		(void*)InterfaceID
	);
	
	return (!Globals.Interfaces[InterfaceID].ThreadID);
#endif
	
}

#endif /*if linux*/