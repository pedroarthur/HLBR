#include "packet_solaris_dlpi.h"
/***************************************************
* Most of this is taken directly from libpcap
***************************************************/

#ifdef _SOLARIS_

#include "packet.h"
#include <stdio.h>
#include <sys/dlpi.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stropts.h>
#include <sys/systeminfo.h>
#include <ctype.h>
#include <memory.h>
#include <sys/bufmod.h>

#define DEBUG

#define MAXDLBUF			8192
#define PCAP_DEV_PREFIX		"/dev"
typedef unsigned int		u_int32;

static u_int32 ctlbuf[MAXDLBUF];
static struct strbuf ctl = {
	MAXDLBUF,
	0,
	(char *)ctlbuf
};


extern GlobalVars	Globals;

/*********************************************************
* Taken from libpcap
*********************************************************/
static int send_request(int fd, char *ptr, int len, char *what){
	struct	strbuf	ctl;
	int	flags;

	ctl.maxlen = 0;
	ctl.len = len;
	ctl.buf = ptr;

	flags = 0;
	if (putmsg(fd, &ctl, (struct strbuf *) NULL, flags) < 0) {
		printf("send_request: putmsg \"%s\": %s", what, strerror(errno));
		return (-1);
	}
	return (0);
}


/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlinforeq(int fd){
	dl_info_req_t req;

	req.dl_primitive = DL_INFO_REQ;

	return (send_request(fd, (char *)&req, sizeof(req), "info"));
}


/*********************************************************
* Taken from libpcap
*********************************************************/
static char* dlstrerror(u_int32 dl_errno){
	static char errstring[6+2+8+1];

	switch (dl_errno) {

	case DL_ACCESS:
		return ("Improper permissions for request");

	case DL_BADADDR:
		return ("DLSAP addr in improper format or invalid");

	case DL_BADCORR:
		return ("Seq number not from outstand DL_CONN_IND");

	case DL_BADDATA:
		return ("User data exceeded provider limit");

	case DL_BADPPA:
		/*
		 * We have separate devices for separate devices;
		 * the PPA is just the unit number.
		 */
		return ("Specified PPA (device unit) was invalid");
		
	case DL_BADPRIM:
		return ("Primitive received not known by provider");

	case DL_BADQOSPARAM:
		return ("QOS parameters contained invalid values");

	case DL_BADQOSTYPE:
		return ("QOS structure type is unknown/unsupported");

	case DL_BADSAP:
		return ("Bad LSAP selector");

	case DL_BADTOKEN:
		return ("Token used not an active stream");

	case DL_BOUND:
		return ("Attempted second bind with dl_max_conind");

	case DL_INITFAILED:
		return ("Physical link initialization failed");

	case DL_NOADDR:
		return ("Provider couldn't allocate alternate address");

	case DL_NOTINIT:
		return ("Physical link not initialized");

	case DL_OUTSTATE:
		return ("Primitive issued in improper state");

	case DL_SYSERR:
		return ("UNIX system error occurred");

	case DL_UNSUPPORTED:
		return ("Requested service not supplied by provider");

	case DL_UNDELIVERABLE:
		return ("Previous data unit could not be delivered");

	case DL_NOTSUPPORTED:
		return ("Primitive is known but not supported");

	case DL_TOOMANY:
		return ("Limit exceeded");

	case DL_NOTENAB:
		return ("Promiscuous mode not enabled");

	case DL_BUSY:
		return ("Other streams for PPA in post-attached");

	case DL_NOAUTO:
		return ("Automatic handling XID&TEST not supported");

	case DL_NOXIDAUTO:
		return ("Automatic handling of XID not supported");

	case DL_NOTESTAUTO:
		return ("Automatic handling of TEST not supported");

	case DL_XIDAUTO:
		return ("Automatic handling of XID response");

	case DL_TESTAUTO:
		return ("Automatic handling of TEST response");

	case DL_PENDING:
		return ("Pending outstanding connect indications");

	default:
		sprintf(errstring, "Error %02x", dl_errno);
		return (errstring);
	}
}

/*********************************************************
* Taken from libpcap
*********************************************************/
static char* dlprim(u_int32 prim){
	static char primbuf[80];

	switch (prim) {

	case DL_INFO_REQ:
		return ("DL_INFO_REQ");

	case DL_INFO_ACK:
		return ("DL_INFO_ACK");

	case DL_ATTACH_REQ:
		return ("DL_ATTACH_REQ");

	case DL_DETACH_REQ:
		return ("DL_DETACH_REQ");

	case DL_BIND_REQ:
		return ("DL_BIND_REQ");

	case DL_BIND_ACK:
		return ("DL_BIND_ACK");

	case DL_UNBIND_REQ:
		return ("DL_UNBIND_REQ");

	case DL_OK_ACK:
		return ("DL_OK_ACK");

	case DL_ERROR_ACK:
		return ("DL_ERROR_ACK");

	case DL_SUBS_BIND_REQ:
		return ("DL_SUBS_BIND_REQ");

	case DL_SUBS_BIND_ACK:
		return ("DL_SUBS_BIND_ACK");

	case DL_UNITDATA_REQ:
		return ("DL_UNITDATA_REQ");

	case DL_UNITDATA_IND:
		return ("DL_UNITDATA_IND");

	case DL_UDERROR_IND:
		return ("DL_UDERROR_IND");

	case DL_UDQOS_REQ:
		return ("DL_UDQOS_REQ");

	case DL_CONNECT_REQ:
		return ("DL_CONNECT_REQ");

	case DL_CONNECT_IND:
		return ("DL_CONNECT_IND");

	case DL_CONNECT_RES:
		return ("DL_CONNECT_RES");

	case DL_CONNECT_CON:
		return ("DL_CONNECT_CON");

	case DL_TOKEN_REQ:
		return ("DL_TOKEN_REQ");

	case DL_TOKEN_ACK:
		return ("DL_TOKEN_ACK");

	case DL_DISCONNECT_REQ:
		return ("DL_DISCONNECT_REQ");

	case DL_DISCONNECT_IND:
		return ("DL_DISCONNECT_IND");

	case DL_RESET_REQ:
		return ("DL_RESET_REQ");

	case DL_RESET_IND:
		return ("DL_RESET_IND");

	case DL_RESET_RES:
		return ("DL_RESET_RES");

	case DL_RESET_CON:
		return ("DL_RESET_CON");

	default:
		(void) sprintf(primbuf, "unknown primitive 0x%x", prim);
		return (primbuf);
	}
}



/*********************************************************
* Taken from libpcap
*********************************************************/
static int recv_ack(int fd, int size, const char *what, char *bufp){
	union	DL_primitives	*dlp;
	struct	strbuf	ctl;
	int	flags;

	ctl.maxlen = MAXDLBUF;
	ctl.len = 0;
	ctl.buf = bufp;

	flags = 0;
	if (getmsg(fd, &ctl, (struct strbuf*)NULL, &flags) < 0) {
		printf("recv_ack: %s getmsg: %s", what, strerror(errno));
		return (-1);
	}

	dlp = (union DL_primitives *) ctl.buf;
	switch (dlp->dl_primitive) {

	case DL_INFO_ACK:
	case DL_BIND_ACK:
	case DL_OK_ACK:
#ifdef DL_HP_PPA_ACK
	case DL_HP_PPA_ACK:
#endif
		/* These are OK */
		break;

	case DL_ERROR_ACK:
		switch (dlp->error_ack.dl_errno) {

		case DL_SYSERR:
			printf("recv_ack: %s: UNIX error - %s", what, strerror(dlp->error_ack.dl_unix_errno));
			break;

		default:
			printf("recv_ack: %s: %s", what, dlstrerror(dlp->error_ack.dl_errno));
			break;
		}
		return (-1);

	default:
		printf("recv_ack: %s: Unexpected primitive ack %s", what, dlprim(dlp->dl_primitive));
		return (-1);
	}

	if (ctl.len < size) {
		printf("recv_ack: %s: Ack too small (%d < %d)", what, ctl.len, size);
		return (-1);
	}
	return (ctl.len);
}


/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlinfoack(int fd, char *bufp){
	return (recv_ack(fd, DL_INFO_ACK_SIZE, "info", bufp));
}


/*******************************************************************
* Split a device name into a device type name and a unit number;
* return the a pointer to the beginning of the unit number, which
* is the end of the device type name, and set "*unitp" to the unit
* number.
*
* Returns NULL on error, and fills "ebuf" with an error message.
********************************************************************/
static char* split_dname(char *device, int *unitp){
	char *cp;
	char *eos;
	int unit;

	/*
	 * Look for a number at the end of the device name string.
	 */
	cp = device + strlen(device) - 1;
	if (*cp < '0' || *cp > '9') {
		printf("%s missing unit number", device);
		return (NULL);
	}

	/* Digits at end of string are unit number */
	while (cp-1 >= device && *(cp-1) >= '0' && *(cp-1) <= '9')
		cp--;

	unit = strtol(cp, &eos, 10);
	if (*eos != '\0') {
		printf("%s bad unit number", device);
		return (NULL);
	}
	*unitp = unit;
	return (cp);
}

/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlattachreq(int fd, u_int32 ppa){
	dl_attach_req_t	req;

	req.dl_primitive = DL_ATTACH_REQ;
	req.dl_ppa = ppa;

	return (send_request(fd, (char *)&req, sizeof(req), "attach"));
}


/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlokack(int fd, const char *what, char *bufp){
	return (recv_ack(fd, DL_OK_ACK_SIZE, what, bufp));
}

/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlbindreq(int fd, u_int32 sap){
	dl_bind_req_t	req;

	memset((char *)&req, 0, sizeof(req));
	req.dl_primitive = DL_BIND_REQ;
	req.dl_sap = sap;
#ifdef DL_CLDLS
	req.dl_service_mode = DL_CLDLS;
#endif

	return (send_request(fd, (char *)&req, sizeof(req), "bind"));
}

/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlbindack(int fd, char *bufp){

	return (recv_ack(fd, DL_BIND_ACK_SIZE, "bind", bufp));
}

/*********************************************************
* Taken from libpcap
*********************************************************/
static int dlpromisconreq(int fd, u_int32 level){
	dl_promiscon_req_t req;

	req.dl_primitive = DL_PROMISCON_REQ;
	req.dl_level = level;

	return (send_request(fd, (char *)&req, sizeof(req), "promiscon"));
}

/*********************************************************
* Taken from libpcap
*********************************************************/
static int strioctl(int fd, int cmd, int len, char *dp){
	struct strioctl str;
	int rc;

	str.ic_cmd = cmd;
	str.ic_timout = -1;
	str.ic_len = len;
	str.ic_dp = dp;
	rc = ioctl(fd, I_STR, &str);

	if (rc < 0)
		return (rc);
	else
		return (str.ic_len);
}


/*********************************************************
* Taken from libpcap
*********************************************************/
static char* get_release(u_int32 *majorp, u_int32 *minorp, u_int32 *microp){
	char *cp;
	static char buf[32];

	*majorp = 0;
	*minorp = 0;
	*microp = 0;
	if (sysinfo(SI_RELEASE, buf, sizeof(buf)) < 0)
		return ("?");
	cp = buf;
	if (!isdigit((unsigned char)*cp))
		return (buf);
	*majorp = strtol(cp, &cp, 10);
	if (*cp++ != '.')
		return (buf);
	*minorp =  strtol(cp, &cp, 10);
	if (*cp++ != '.')
		return (buf);
	*microp =  strtol(cp, &cp, 10);
	return (buf);
}

/*********************************************
* Open an interface via Solaris DLPI
**********************************************/
int OpenInterfaceSolarisDLPI(int InterfaceID){
	register char *cp;
	int ppa;
	register dl_info_ack_t *infop;
	u_int32 ss, flag;
	register char *release;
	u_int32 osmajor, osminor, osmicro;
	u_int32 buf[MAXDLBUF];
	char dname[100];
	char dname2[100];
	
	InterfaceRec*	interface;
	
	interface=&Globals.Interfaces[InterfaceID];

	/******************************************************
	* Break up the interface name in to unit and number
	******************************************************/
	cp = split_dname(interface->Name, &ppa);
	if (cp == NULL){
		printf("I couldn't understand the interface name\n");
		return FALSE;
	}

	/*
	 * If the device name begins with "/", assume it begins with
	 * the pathname of the directory containing the device to open;
	 * otherwise, concatenate the device directory name and the
	 * device name.
	 */
	if (*interface->Name == '/')
		strncpy(dname, interface->Name, sizeof(dname));
	else
		snprintf(dname, sizeof(dname), "%s/%s", PCAP_DEV_PREFIX,
		    interface->Name);

	/*
	 * Make a copy of the device pathname, and then remove the unit
	 * number from the device pathname.
	 */
	strncpy(dname2, dname, sizeof(dname));
	*(dname + strlen(dname) - strlen(cp)) = '\0';

	/* Try device without unit number */
	if ((interface->FD = open(dname, O_RDWR)) < 0) {
		if (errno != ENOENT) {
			printf("%s: %s", dname, strerror(errno));
			return FALSE;
		}

		/* Try again with unit number */
		if ((interface->FD = open(dname2, O_RDWR)) < 0) {
			printf("%s: %s", dname2, strerror(errno));
			return FALSE;
		}
		/* XXX Assume unit zero */
		ppa = 0;
	}

	/*
	** Attach if "style 2" provider
	*/
	if (dlinforeq(interface->FD) < 0 ||
	    dlinfoack(interface->FD, (char *)buf) < 0)
		return FALSE;
	infop = &((union DL_primitives *)buf)->info_ack;
	if (infop->dl_provider_style == DL_STYLE2 &&
	    (dlattachreq(interface->FD, ppa) < 0 ||
	    dlokack(interface->FD, "attach", (char *)buf) < 0))
		return FALSE;

	/*
	** Bind (defer if using HP-UX 9 or HP-UX 10.20, totally skip if
	** using SINIX)
	*/

	if (dlbindreq(interface->FD, 0) < 0 ||
	    dlbindack(interface->FD, (char *)buf) < 0)
		return FALSE;

	/* Enable promiscuous */
	if (dlpromisconreq(interface->FD, DL_PROMISC_PHYS) < 0 ||
	    dlokack(interface->FD, "promisc_phys", (char *)buf) < 0)
		return FALSE;   

	/****************************************************
	* Try to enable multicast (you would have thought
	* promiscuous would be sufficient). 
	****************************************************/

	if (dlpromisconreq(interface->FD, DL_PROMISC_MULTI) < 0 ||
	    dlokack(interface->FD, "promisc_multi", (char *)buf) < 0)
		printf("WARNING: DL_PROMISC_MULTI failed\n");

	/***************************************************
	* Try to enable sap 
	***************************************************/

	if ((dlpromisconreq(interface->FD, DL_PROMISC_SAP) < 0 ||
	    dlokack(interface->FD, "promisc_sap", (char *)buf) < 0)) {
		/* Not fatal if promisc since the DL_PROMISC_PHYS worked */
		printf("WARNING: DL_PROMISC_SAP failed\n");
	}

	/*****************************************************************
	* This is a non standard SunOS hack to get the ethernet header.
	*****************************************************************/
	if (strioctl(interface->FD, DLIOCRAW, 0, NULL) < 0) {
		printf("DLIOCRAW: %s", strerror(errno));
		return FALSE;
	}

	/***************************************************************
	* Another non standard call to get the data nicely buffered
	***************************************************************/
	if (ioctl(interface->FD, I_PUSH, "bufmod") != 0) {
		printf("I_PUSH bufmod: %s", strerror(errno));
		return FALSE;
	}

	/*
	** Now that the bufmod is pushed lets configure it.
	**
	** There is a bug in bufmod(7). When dealing with messages of
	** less than snaplen size it strips data from the beginning not
	** the end.
	**
	** This bug is supposed to be fixed in 5.3.2. Also, there is a
	** patch available. Ask for bugid 1149065.
	*/
	ss = 1600;
	release = get_release(&osmajor, &osminor, &osmicro);
	if (osmajor == 5 && (osminor <= 2 || (osminor == 3 && osmicro < 2)) &&
	    getenv("BUFMOD_FIXED") == NULL) {
		fprintf(stderr,
		"WARNING: bufmod is broken in SunOS %s; ignoring snaplen.\n",
		    release);
		ss = 0;
	}
	if (ss > 0 &&
	    strioctl(interface->FD, SBIOCSSNAP, sizeof(ss), (char *)&ss) != 0) {
		printf("SBIOCSSNAP: %s", strerror(errno));
		return FALSE;
	}

	/*
	** Set up the bufmod flags
	*/
	if (strioctl(interface->FD, SBIOCGFLAGS, sizeof(flag), (char *)&flag) < 0) {
		printf("SBIOCGFLAGS: %s", strerror(errno));
		return FALSE;
	}
	flag |= SB_NO_DROPS;
	if (strioctl(interface->FD, SBIOCSFLAGS, sizeof(flag), (char *)&flag) != 0) {
		printf("SBIOCSFLAGS: %s", strerror(errno));
		return FALSE;
	}

	/*
	** As the last operation flush the read side.
	*/
	if (ioctl(interface->FD, I_FLUSH, FLUSHR) != 0) {
		printf("FLUSHR: %s", strerror(errno));
		return FALSE;
	}

	interface->IsPollable=TRUE;

	return TRUE;
}

/**********************************************
* Read a packet off of a Solaris DLPI
**********************************************/
int ReadPacketSolarisDLPI(int InterfaceID){
	InterfaceRec*	Interface;
	int				PacketSlot;
	PacketRec*		p;
	
	register int cc, n, caplen, origlen;
	register u_char *bp, *ep, *pk;
	register struct sb_hdr *sbp;
	struct sb_hdr sbhdr;
	int flags;
	struct strbuf data;

	static char readbuff[MAXDLBUF];
		
#ifdef DEBUGPATH
	printf("In ReadPacketSolarisDLPI\n");
#endif

	Interface=&Globals.Interfaces[InterfaceID];
	
	flags = 0;
	cc=0;
	/*read in the packets*/
	data.buf = (char *)readbuff;
	data.maxlen = MAXDLBUF;
	data.len = 0;
	do {
		if (getmsg(Interface->FD, &ctl, &data, &flags) < 0) {
			/* Don't choke when we get ptraced */
			if (errno == EINTR) {
				cc = 0;
				continue;
			}
			return FALSE;
		}
		cc = data.len;
	} while (cc == 0);
	bp = readbuff;
	
	/* Loop through packets */
	ep = bp + cc;
	n = 0;
	while (bp < ep) {
		/*parse the next packet off the buffer*/
		if ((long)bp & 3) {
			sbp = &sbhdr;
			memcpy(sbp, bp, sizeof(*sbp));
		} else
			sbp = (struct sb_hdr *)bp;
			
		pk = bp + sizeof(*sbp);
		bp += sbp->sbh_totlen;
		origlen = sbp->sbh_origlen;
		caplen = sbp->sbh_msglen;

		/*push this packet on the pending queue*/
		if ( (PacketSlot=GetEmptyPacket())==-1){
			printf("Unable to allocate packet for reading\n");
			return FALSE;		
		}		
		p=&Globals.Packets[PacketSlot];
		p->InterfaceNum=InterfaceID;
		p->PacketLen=sbp->sbh_msglen;	
		p->tv=sbp->sbh_timestamp;
		memcpy(p->RawPacket, ((char*)sbp)+sizeof(struct sb_hdr), p->PacketLen);
		
		if (!AddPacketToPending(PacketSlot)){
			printf("Couldn't add packet to pending queue\n");
			ReturnEmptyPacket(PacketSlot);
			return FALSE;
		}
			
		/*end pushing packet*/
	}

	return TRUE;
}

/***************************************************
* Send a packet off to the interface
****************************************************/
int WritePacketSolarisDLPI(int InterfaceID, unsigned char* Packet, int PacketLen){
	InterfaceRec*	interface;
#ifdef DEBUGPATH
	printf("In WritePacketSolarisDLPI\n");
#endif

	interface=&Globals.Interfaces[InterfaceID];
	
	
	return TRUE;
}

/**********************************************
* The thread func
**********************************************/
void* SolarisDLPILoopFunc(void* v){
	int				InterfaceID;

#ifdef DEBUGPATH
	printf("In SolarisDLPILoopFunc\n");
#endif

	InterfaceID=(int)v;
	while (!Globals.Done){
		ReadPacketSolarisDLPI(InterfaceID);
	}
	
	return NULL;
}

/**********************************************
* Start a thread to continuously read
**********************************************/
int LoopThreadSolarisDLPI(int InterfaceID){
#ifdef DEBUGPATH
	printf("In loopThreadSolarisDLPI\n");
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
		SolarisDLPILoopFunc,
		(void*)InterfaceID
	);
	
	return (!Globals.Interfaces[InterfaceID].ThreadID);
#endif
	
}

#endif /*if solaris*/
