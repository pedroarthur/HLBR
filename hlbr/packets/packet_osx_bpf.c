#include "packet_osx_bpf.h"
#ifdef _OSX_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <net/bpf.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DEBUG

#define FATAL		1
#define NONFATAL	0

extern GlobalVars	Globals;

/***********************************************
* Open up a bpf
***********************************************/
static int
bpf_open()
{
	int     fd;
	int     n = 0;
	char    device[sizeof "/dev/bpf0000000000"];

	/* Go through all the minors and find one that isn't in use. */
	do {
		(void) snprintf(device, sizeof device, "/dev/bpf%d", n++);
		fd = open(device, O_RDWR);
	} while (fd < 0 && errno == EBUSY);

	if (fd < 0) {
		err(FATAL, "%s: %s", device, strerror(errno));
		/* NOTREACHED */
	}
	return fd;
}

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
* Open an interface OSX BPF's
**********************************************/
int OpenInterfaceOSXBPF(int InterfaceID){
	int     		fd;
	struct 			ifreq ifr;
	u_int   		dlt;
	int     		immediate;
	int				promisc;
	int				link;
	struct timeval	timeout;
	InterfaceRec*	Interface;

	DEBUGPATH;

	Interface=&Globals.Interfaces[InterfaceID];

#ifdef DEBUG
	printf("Opening interface %s\n", Interface->Name);
#endif

	fd = bpf_open();

	(void) strncpy(ifr.ifr_name, Interface->Name, sizeof ifr.ifr_name);
	if (ioctl(fd, BIOCSETIF, (caddr_t) & ifr) < 0) {
		err(FATAL, "BIOCSETIF: %s", strerror(errno));
		/* NOTREACHED */
	}
	/* Check that the data link layer is an Ethernet; this code won't work
	 * with anything else. */
	if (ioctl(fd, BIOCGDLT, (caddr_t) & dlt) < 0) {
		err(FATAL, "BIOCGDLT: %s", strerror(errno));
		/* NOTREACHED */
	}
	if (dlt != DLT_EN10MB) {
		err(FATAL, "%s is not an ethernet", Interface->Name);
		/* NOTREACHED */
	}
	/*turn off automatic filling of the mac address*/
	link=1;
	if (ioctl(fd, BIOCSHDRCMPLT, &link) < 0){
		printf("Couldn't turn off auto mac address\n");
		exit(0);
	}
	/* Switch the interface into promisc mode*/
	promisc=1;
	if (ioctl(fd, BIOCPROMISC, &promisc) < 0) {
		printf("Couldn't enter promisc mode\n");
		exit(1);
	}
	if (dlt != DLT_EN10MB) {
		err(FATAL, "%s is not an ethernet", Interface->Name);
		/* NOTREACHED */
	}	
	
	/* Set immediate mode so packets are processed as they arrive. */
	immediate = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) {
		err(FATAL, "BIOCIMMEDIATE: %s", strerror(errno));
		/* NOTREACHED */
	}

	/* Set immediate mode so packets are processed as they arrive. */
	timeout.tv_sec=0;
	timeout.tv_usec=1;
	if (ioctl(fd, BIOCSRTIMEOUT, &timeout) < 0) {
		err(FATAL, "BIOCSRTIMEOUT: %s", strerror(errno));
		/* NOTREACHED */
	}


	/* Set immediate mode so packets are processed as they arrive. */
	immediate = 0;
	if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) {
		err(FATAL, "BIOCIMMEDIATE: %s", strerror(errno));
		/* NOTREACHED */
	}

	Interface->FD=fd;
	Interface->MTU=GetIfrMTU(Interface->Name);
	if (Interface->MTU==-1) Interface->MTU=1500;

	Interface->IsPollable=TRUE;

	return TRUE;
}

/**********************************************
* Read a packet off of the bpf
* TODO: Get rid of the malloc
**********************************************/
int ReadPacketOSXBPF(int InterfaceID){
	int 			bufsize1, cc;
	u_char			*buf1, *bp, *ep;
	
	InterfaceRec*	interface;
	PacketRec*		p;
	int		PacketSlot;

	DEBUGPATH;
	
	interface=&Globals.Interfaces[InterfaceID];
	
	/*Get the sizes of the buffers*/
	if (ioctl(interface->FD, BIOCGBLEN, (caddr_t) & bufsize1) < 0) {
		err(FATAL, "BIOCGBLEN: %s", strerror(errno));
		/* NOTREACHED */
	}
#ifdef DEBUG1	
	printf("Buffer size1 is %i\n",bufsize1);
#endif
		 
	buf1 = (u_char *) malloc((unsigned) bufsize1);
	if (buf1 == 0) {
		err(FATAL, "malloc: %s", strerror(errno));
		/* NOTREACHED */
	}
		
	again:
	cc = read(interface->FD, (char *) buf1, bufsize1);
#ifdef DEBUG1				
	printf("Read %i bytes from the bpf\n",cc);
#endif					

	if (cc==0){
		free(buf1);
		return TRUE;
	}

	/* Don't choke when we get ptraced */
	if (cc < 0 && errno == EINTR)
		goto again;
	if (cc < 0) {
		if (errno == EINVAL &&
	    	(lseek(interface->FD, 0, SEEK_CUR) + bufsize1) < 0) {
				(void) lseek(interface->FD, 0, 0);
				goto again;
		}
		err(FATAL, "read: %s", strerror(errno));
		
		/* NOTREACHED */
	}
	
	/* Loop through the packet(s) */
#define bhp ((struct bpf_hdr *)bp)
	bp = buf1;
	ep = bp + cc;
	while (bp < ep) {
		register int caplen, hdrlen;

		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;
		
#ifdef DEBUG
		printf("This packet is %u bytes\n",bhp->bh_caplen);
#endif	
		/*Get a new packet*/
		PacketSlot=GetEmptyPacket();
		if (PacketSlot==PACKET_NONE) return FALSE;
		p=&Globals.Packets[PacketSlot];
		p->InterfaceNum=InterfaceID;

		/*fill it in*/
		p->PacketLen=bhp->bh_caplen;					
		p->tv.tv_sec=bhp->bh_tstamp.tv_sec;
		p->tv.tv_usec=bhp->bh_tstamp.tv_usec;
		memcpy(p->RawPacket, bp+18, p->PacketLen);
		
		/*send it off*/
		if (!AddPacketToPending(PacketSlot)){
			printf("Coulnd't add packet to pending queue\n");
			ReturnEmptyPacket(PacketSlot);
			free(buf1);
			return FALSE;
		}
		bp += BPF_WORDALIGN(hdrlen + caplen);
	}

	free(buf1);	
	return TRUE;
}

/***************************************************
* Send a packet off to the bpf
****************************************************/
int WritePacketOSXBPF(int InterfaceID, unsigned char* Packet, int PacketLen){
	InterfaceRec*	interface;
	int 			cc;
	
	DEBUGPATH;

	interface=&Globals.Interfaces[InterfaceID];

#ifdef DEBUG
	printf("Writing packet OBX to interface %s\n",interface->Name);
#endif
	
	cc=write(interface->FD, Packet, PacketLen);
	if (cc!=PacketLen){
#ifdef DEBUG
		printf("write_packet: Failed to write packet ot interface %s\n",interface->Name);
#endif
		return FALSE;
	}

	return TRUE;
}

/**********************************************
* The thread func
**********************************************/
void* OSXBPFLoopFunc(void* v){
	int				InterfaceID;

	DEBUGPATH;

	InterfaceID=(int)v;
	while (!Globals.Done){
		ReadPacketOSXBPF(InterfaceID);
	}
	
	return NULL;
}

/**********************************************
* Start a thread to continuously read
**********************************************/
int LoopThreadOSXBPF(int InterfaceID){
  DEBUGPATH;

#ifndef HAS_THREADS
	return FALSE;
#else

#ifdef DEBUG
	printf("Starting Thread for interface %s\n",Globals.Interfaces[InterfaceID].Name);
#endif

	Globals.Interfaces[InterfaceID].ThreadID=pthread_create(
		&Globals.Interfaces[InterfaceID].Thread,
		NULL,
		OSXBPFLoopFunc,
		(void*)InterfaceID
	);
	
	return (!Globals.Interfaces[InterfaceID].ThreadID);	
#endif	
}

#endif /*if OSX*/
