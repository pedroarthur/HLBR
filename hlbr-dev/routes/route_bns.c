/************************************************
* This module handles BNS style honeypot routing
* It's similar to macfilter
************************************************/
#include "route_bns.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../packets/packet.h"
#include "../engine/num_list.h"
#include "../decoders/decode.h"
#include "../decoders/decode_ethernet.h"
#include "../decoders/decode_arp.h"
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include "../decoders/decode_udp.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif

#define BNS_PRODUCTION		1
#define BNS_HONEY			2
#define BNS_INTERNET		3

BNS_MAC	BMAC[MAX_BNS];
int		BNSNumMac;
BNS_IP	BIP[MAX_BNS];
int		BNSNumIP;

int		InternetIF;
int		ProductionIF;
int		HoneyIF;

int		EthernetDecoderID;
int		ARPDecoderID;
int		IPDecoderID;
int		TCPDecoderID;
int		UDPDecoderID;

/*TODO: put these in a num list*/
typedef struct bns_note{
	unsigned int	HIP;
	unsigned short	HPort;
	unsigned int	IIP;
	unsigned int	IPort;
	unsigned char	Proto;
} BNSNote;

#define BNS_MAX_NOTES	128

BNSNote	Notes[BNS_MAX_NOTES];
int	ThisNote;

//#define DEBUG

extern GlobalVars	Globals;


/**************************************
* Windows boxes don't arp properly, so
* we need to tickle them occasionally
***************************************/
int SendARP(unsigned int IP, int Interface){
	int			NewPacketSlot;
	EtherHdr*	Eth;
	ARPHdr*		Arp;
	ARPEtherIP*	ArpEth;
	PacketRec*	p;
	
#ifdef DEBUGPATH
	printf("In SendARP\n");
#endif

	NewPacketSlot=GetEmptyPacket();
	if (!NewPacketSlot==PACKET_NONE){
#ifdef DEBUG
		printf("Couldn't get a packet for the ARP request\n");
#endif	
		return FALSE;
	}
	
	p=&Globals.Packets[NewPacketSlot];
	p->RawPacket=p->TypicalPacket;
	
	Eth=(EtherHdr*)p->RawPacket;
	Eth->DstMac[0]=0xFF;
	Eth->DstMac[1]=0xFF;
	Eth->DstMac[2]=0xFF;
	Eth->DstMac[3]=0xFF;
	Eth->DstMac[4]=0xFF;
	Eth->DstMac[5]=0xFF;
	Eth->SrcMac[0]=0x00;
	Eth->SrcMac[1]=0x00;
	Eth->SrcMac[2]=0x00;
	Eth->SrcMac[3]=0x00;
	Eth->SrcMac[4]=0x00;
	Eth->SrcMac[5]=0x00;
	Eth->Type=htons(ETHERNET_TYPE_ARP);
	p->PacketLen+=sizeof(EtherHdr);

	Arp=(ARPHdr*)(p->RawPacket+sizeof(EtherHdr));
	Arp->HardwareType=htons(ARP_TYPE_ETHERNET);
	Arp->ProtocolType=htons(ARP_TYPE_IP);
	Arp->HardwareLen=6;
	Arp->ProtocolLen=4;
	Arp->Operation=htons(ARP_OP_REQUEST);
	p->PacketLen+=sizeof(ARPHdr);
	
	ArpEth=(ARPEtherIP*)(p->RawPacket+sizeof(EtherHdr)+sizeof(ARPHdr));
	ArpEth->SenderMac[0]=0x00;
	ArpEth->SenderMac[1]=0x00;
	ArpEth->SenderMac[2]=0x00;
	ArpEth->SenderMac[3]=0x00;
	ArpEth->SenderMac[4]=0x00;
	ArpEth->SenderMac[5]=0x00;
	ArpEth->SenderIP[0]=10;
	ArpEth->SenderIP[1]=10;
	ArpEth->SenderIP[2]=10;
	ArpEth->SenderIP[3]=10;
	ArpEth->TargetMac[0]=0x00;
	ArpEth->TargetMac[1]=0x00;
	ArpEth->TargetMac[2]=0x00;
	ArpEth->TargetMac[3]=0x00;
	ArpEth->TargetMac[4]=0x00;
	ArpEth->TargetMac[5]=0x00;
	ArpEth->TargetIP[0]=((char*)&IP)[0];
	ArpEth->TargetIP[1]=((char*)&IP)[1];
	ArpEth->TargetIP[2]=((char*)&IP)[2];
	ArpEth->TargetIP[3]=((char*)&IP)[3];
	p->PacketLen+=sizeof(ARPEtherIP);

	p->TargetInterface=Interface;

	WritePacket(NewPacketSlot);

	ReturnEmptyPacket(NewPacketSlot);

	return FALSE;
}

/***************************************
* Return the BNS rec that has this Mac
***************************************/
int FindMac(unsigned char Mac[6]){
	int i;
	
#ifdef DEBUGPATH
	printf("In FindMac\n");
#endif	

	for (i=0;i<BNSNumMac;i++){
		if ( (BMAC[i].Mac[0]==Mac[0]) &&
             (BMAC[i].Mac[1]==Mac[1]) &&
             (BMAC[i].Mac[2]==Mac[2]) &&
             (BMAC[i].Mac[3]==Mac[3]) &&
             (BMAC[i].Mac[4]==Mac[4]) &&
             (BMAC[i].Mac[5]==Mac[5])
		) return i;
	}

	return -1;
}

/**************************************
* Add the Mac to the list
**************************************/
int AddMac(unsigned char Mac[6], int Interface){

#ifdef DEBUGPATH
	printf("In AddMac\n");
#endif

	if (BNSNumMac==MAX_BNS){
#ifdef DEBUG
		printf("Out of slots to hold BNS Mac records\n");
#endif	
		return -1;
	}

	if ( (Mac[0]==0xFF) &&
		(Mac[1]==0xFF) &&
		(Mac[2]==0xFF) &&
		(Mac[3]==0xFF) &&
		(Mac[4]==0xFF) &&
		(Mac[5]==0xFF)
	){
#ifdef DEBUG
		printf("Ignoring Broadcast MAC\n");
#endif	
	}

	bzero(&BMAC[BNSNumMac], sizeof(BNS_MAC));
	BMAC[BNSNumMac].Mac[0]=Mac[0];
	BMAC[BNSNumMac].Mac[1]=Mac[1];
	BMAC[BNSNumMac].Mac[2]=Mac[2];
	BMAC[BNSNumMac].Mac[3]=Mac[3];
	BMAC[BNSNumMac].Mac[4]=Mac[4];
	BMAC[BNSNumMac].Mac[5]=Mac[5];
	BMAC[BNSNumMac].Interface=Interface;

	BNSNumMac++;
	
	return BNSNumMac-1;
}



/***************************************
* Return the BNS rec that has this IP
***************************************/
int FindIP(unsigned int IP){
	int i;
	
#ifdef DEBUGPATH
	printf("In FindIP\n");
#endif	

	for (i=0;i<BNSNumIP;i++){
		if (BIP[i].IP==IP) return i;
	}

	return -1;
}

/**************************************
* Add the IP to the list
**************************************/
int UpdateIP(unsigned int IP, unsigned char Mac[6], int Interface){
	int	IPID;
	
#ifdef DEBUGPATH
	printf("In AddIP\n");
#endif

	IPID=FindIP(IP);

	if ((IPID==-1) && (BNSNumIP==MAX_BNS)){
#ifdef DEBUG
		printf("Out of slots to hold BNS IP records\n");
#endif	
		return -1;
	}

#ifdef DEBUG
	if (Interface==BNS_HONEY)
		printf("%s(%02X:%02X:%02X:%02X:%02X:%02X) is on Honey\n",
			inet_ntoa(*(struct in_addr*)&IP),
			Mac[0],Mac[1],Mac[2],Mac[3],Mac[4],Mac[5]
		);
	else
		printf("%s(%02X:%02X:%02X:%02X:%02X:%02X) is on Production\n",
			inet_ntoa(*(struct in_addr*)&IP),
			Mac[0],Mac[1],Mac[2],Mac[3],Mac[4],Mac[5]
		);	
#endif
	
	if (IPID==-1){ 
		/*this one's new*/
		IPID=BNSNumIP;
		bzero(&BIP[IPID], sizeof(BNS_IP));
		BIP[IPID].IP=IP;
		BNSNumIP++;
		BIP[IPID].HoneyMac[0]=0xFF;
		BIP[IPID].HoneyMac[1]=0xFF;
		BIP[IPID].HoneyMac[2]=0xFF;
		BIP[IPID].HoneyMac[3]=0xFF;
		BIP[IPID].HoneyMac[4]=0xFF;
		BIP[IPID].HoneyMac[5]=0xFF;		
		BIP[IPID].ProdMac[0]=0xFF;
		BIP[IPID].ProdMac[1]=0xFF;
		BIP[IPID].ProdMac[2]=0xFF;
		BIP[IPID].ProdMac[3]=0xFF;
		BIP[IPID].ProdMac[4]=0xFF;
		BIP[IPID].ProdMac[5]=0xFF;
		BIP[IPID].HasHoney=FALSE;
		BIP[IPID].HasProd=FALSE;
	}

	switch (Interface){
	case BNS_HONEY:
		BIP[IPID].HoneyMac[0]=Mac[0];
		BIP[IPID].HoneyMac[1]=Mac[1];
		BIP[IPID].HoneyMac[2]=Mac[2];
		BIP[IPID].HoneyMac[3]=Mac[3];
		BIP[IPID].HoneyMac[4]=Mac[4];
		BIP[IPID].HoneyMac[5]=Mac[5];
		BIP[IPID].HasHoney=TRUE;
		break;
	case BNS_PRODUCTION:
		BIP[IPID].ProdMac[0]=Mac[0];
		BIP[IPID].ProdMac[1]=Mac[1];
		BIP[IPID].ProdMac[2]=Mac[2];
		BIP[IPID].ProdMac[3]=Mac[3];
		BIP[IPID].ProdMac[4]=Mac[4];
		BIP[IPID].ProdMac[5]=Mac[5];
		BIP[IPID].HasProd=TRUE;
		break;
	default:
		return -1;
	}
		
	return IPID;
}

/**************************************
* If this is a normal IP packet...
**************************************/
int HandleIPPacket(int PacketSlot, IPData* IData){
	PacketRec*		p;
	int				SrcSlot;
	int				DstSlot;
	EthernetData*	EData;
	TCPData*		TData=NULL;
	UDPData*		UData=NULL;
	
	int				i;
	int				IPID;
	
#ifdef DEBUGPATH
	printf("In HandleIPPacket\n");
#endif
	p=&Globals.Packets[PacketSlot];

	/*pull out the ethernet header*/
	if (!GetDataByID(p->PacketSlot, EthernetDecoderID, (void**)&EData)){
#ifdef DEBUG
		printf("This is an Ethernet packet\n");
#endif	
		return ROUTE_RESULT_DROP;
	}

	/*pull out the tcp header if it exists*/
	GetDataByID(p->PacketSlot, TCPDecoderID, (void**)&TData);

	/*pull out the udp header if it exists*/
	GetDataByID(p->PacketSlot, UDPDecoderID, (void**)&UData);


	/*go find the src*/
	SrcSlot=FindMac(EData->Header->SrcMac);
	/*if not found, add it*/
	if (SrcSlot==-1){
#ifdef DEBUG
		printf("We've never seen src %s before\n",inet_ntoa(*(struct in_addr*)&IData->Header->saddr));
#endif	
		SrcSlot=AddMac(EData->Header->SrcMac, p->InterfaceNum);
	}
	
	/*go find the dst*/
	DstSlot=FindMac(EData->Header->DstMac);
	/*if not found, drop the packet*/
	if (DstSlot==-1){
#ifdef DEBUG
		printf("We don't know where to send %s\n",inet_ntoa(*(struct in_addr*)&IData->Header->daddr));
#endif	
		SendARP(IData->Header->daddr, ProductionIF);
		SendARP(IData->Header->daddr, HoneyIF);
		SendARP(IData->Header->daddr, InternetIF);

		return ROUTE_RESULT_DROP;
	}

	/*we have a src and a dst*/
#ifdef DEBUG
	printf("%s+%i->",inet_ntoa(*(struct in_addr*)&IData->Header->saddr), BMAC[SrcSlot].Interface);
	printf("%s+%i\n",inet_ntoa(*(struct in_addr*)&IData->Header->daddr), BMAC[DstSlot].Interface);
#endif	
	
	/*check to see if the src and dst interface is the same*/
	if (BMAC[SrcSlot].Interface==BMAC[DstSlot].Interface){
#ifdef DEBUG
		printf("This is passing traffic, ignore\n");
#endif	
		return ROUTE_RESULT_DROP;
	}

	if (p->InterfaceNum==ProductionIF){
#ifdef DEBUG
		printf("From Production, send out Internet\n");
#endif	
		p->TargetInterface=InternetIF;
		return ROUTE_RESULT_DONE;
	}else if (p->InterfaceNum==HoneyIF){
#ifdef DEBUG
		printf("From Honeypot, Note, Mangle, and send out Internet\n");
#endif	

		/*make note of the connection so we can route return packets*/
		if (TData){
#ifdef DEBUG		
			printf("Making note of %s:%u\n",inet_ntoa(*(struct in_addr*)&IData->Header->saddr),ntohs(TData->Header->source));
#endif			
			/*TODO: These will go in a NUM_List*/
			/*This is very slow*/
			Notes[ThisNote].HIP=IData->Header->saddr;
			Notes[ThisNote].HPort=TData->Header->source;
			Notes[ThisNote].IIP=IData->Header->daddr;
			Notes[ThisNote].IPort=TData->Header->dest;
			Notes[ThisNote].Proto=IData->Header->protocol;
			ThisNote++;
			if (ThisNote>=BNS_MAX_NOTES) ThisNote=0;			
		}else if (UData){
#ifdef DEBUG		
			printf("Making note of %s:%u\n",inet_ntoa(*(struct in_addr*)&IData->Header->saddr),ntohs(UData->Header->source));
#endif		
			/*TODO: These will go in a NUM_List*/			
			Notes[ThisNote].HIP=IData->Header->saddr;
			Notes[ThisNote].HPort=UData->Header->source;
			Notes[ThisNote].IIP=IData->Header->daddr;
			Notes[ThisNote].IPort=UData->Header->dest;
			Notes[ThisNote].Proto=IData->Header->protocol;
			ThisNote++;
			if (ThisNote>=BNS_MAX_NOTES) ThisNote=0;
		}else{
#ifdef DEBUG
			printf("We can only keep state on TCP and UDP\n");
#endif		
		}

		/*TODO: Look up the correct src mac*/
		
		p->TargetInterface=InternetIF;
		return ROUTE_RESULT_DONE;
	}else if (p->InterfaceNum==InternetIF){
#ifdef DEBUG
		printf("From Internet.  Check the Notes.\n");
#endif	
		/*see if this ip is blacklisted*/
#ifdef DEBUG		
		printf("Checking to see if %s is blacklisted\n",inet_ntoa(*(struct in_addr*)&IData->Header->saddr));
#endif		
		if (IsInListTime(BNSRerouteList, ntohl(IData->Header->saddr),p->tv.tv_sec)){
#ifdef DEBUG
			printf("This IP is blacklisted. Routing to Honeypot\n");
#endif		
			/*mangle*/
			IPID=FindIP(IData->Header->daddr);
			if (IPID==-1){
#ifdef DEBUG
				printf("1Couldn't find this IP\n");
#endif					
				SendARP(IData->Header->daddr, HoneyIF);

				EData->Header->DstMac[0]=0xFF;
				EData->Header->DstMac[1]=0xFF;
				EData->Header->DstMac[2]=0xFF;
				EData->Header->DstMac[3]=0xFF;
				EData->Header->DstMac[4]=0xFF;
				EData->Header->DstMac[5]=0xFF;
			}else{		
				if (!BIP[IPID].HasHoney){
#ifdef DEBUG
					printf("IP found, no honey record\n");
#endif				
					SendARP(IData->Header->daddr, HoneyIF);
				}						
				EData->Header->DstMac[0]=BIP[IPID].HoneyMac[0];
				EData->Header->DstMac[1]=BIP[IPID].HoneyMac[1];
				EData->Header->DstMac[2]=BIP[IPID].HoneyMac[2];
				EData->Header->DstMac[3]=BIP[IPID].HoneyMac[3];
				EData->Header->DstMac[4]=BIP[IPID].HoneyMac[4];
				EData->Header->DstMac[5]=BIP[IPID].HoneyMac[5];
			}

			p->TargetInterface=HoneyIF;
			return ROUTE_RESULT_DONE;
		}
	
		/*see if there is a note*/
		if (TData){
			for (i=0;i<BNS_MAX_NOTES;i++){
				if ( (Notes[i].HIP==IData->Header->daddr) &&
				     (Notes[i].HPort==TData->Header->dest) &&
					 (Notes[i].IIP==IData->Header->saddr) &&
				     (Notes[i].IPort==TData->Header->source)
				){
#ifdef DEBUG
					printf("Found Note Sending out Honey\n");
#endif				
					/*mangle*/
					IPID=FindIP(IData->Header->daddr);
					if (IPID==-1){
#ifdef DEBUG
						printf("2Couldn't find this IP\n");
#endif					
						SendARP(IData->Header->daddr, HoneyIF);
						
						EData->Header->DstMac[0]=0xFF;
						EData->Header->DstMac[1]=0xFF;
						EData->Header->DstMac[2]=0xFF;
						EData->Header->DstMac[3]=0xFF;
						EData->Header->DstMac[4]=0xFF;
						EData->Header->DstMac[5]=0xFF;
					}else{		
						if (!BIP[IPID].HasHoney){
#ifdef DEBUG
							printf("2IP found, no honey record\n");
#endif				
							SendARP(IData->Header->daddr, HoneyIF);
						}
						EData->Header->DstMac[0]=BIP[IPID].HoneyMac[0];
						EData->Header->DstMac[1]=BIP[IPID].HoneyMac[1];
						EData->Header->DstMac[2]=BIP[IPID].HoneyMac[2];
						EData->Header->DstMac[3]=BIP[IPID].HoneyMac[3];
						EData->Header->DstMac[4]=BIP[IPID].HoneyMac[4];
						EData->Header->DstMac[5]=BIP[IPID].HoneyMac[5];
					}

					p->TargetInterface=HoneyIF;
					return ROUTE_RESULT_DONE;
				}
			}		
		}else if (UData){
			for (i=0;i<BNS_MAX_NOTES;i++){
				if ( (Notes[i].HIP==IData->Header->daddr) &&
				     (Notes[i].HPort==UData->Header->dest) &&
					 (Notes[i].IIP==IData->Header->saddr) &&
				     (Notes[i].IPort==UData->Header->source)
				){
#ifdef DEBUG
					printf("Found Note Sending out Honey\n");
#endif				
					/*mangle*/
					IPID=FindIP(IData->Header->daddr);
					if (IPID==-1){
#ifdef DEBUG
						printf("3Couldn't find this IP\n");
#endif					
						SendARP(IData->Header->daddr, HoneyIF);

						EData->Header->DstMac[0]=0xFF;
						EData->Header->DstMac[1]=0xFF;
						EData->Header->DstMac[2]=0xFF;
						EData->Header->DstMac[3]=0xFF;
						EData->Header->DstMac[4]=0xFF;
						EData->Header->DstMac[5]=0xFF;
					}else{		
						if (!BIP[IPID].HasHoney){
#ifdef DEBUG
							printf("3IP found, no honey record\n");
#endif				
							SendARP(IData->Header->daddr, HoneyIF);
						}						
						EData->Header->DstMac[0]=BIP[IPID].HoneyMac[0];
						EData->Header->DstMac[1]=BIP[IPID].HoneyMac[1];
						EData->Header->DstMac[2]=BIP[IPID].HoneyMac[2];
						EData->Header->DstMac[3]=BIP[IPID].HoneyMac[3];
						EData->Header->DstMac[4]=BIP[IPID].HoneyMac[4];
						EData->Header->DstMac[5]=BIP[IPID].HoneyMac[5];
					}
					
					p->TargetInterface=HoneyIF;
					return ROUTE_RESULT_DONE;
				}
			}				
		}

#ifdef DEBUG
		printf("Sending out Production\n");
#endif
		p->TargetInterface=ProductionIF;
		return ROUTE_RESULT_DONE;
	}
	
	p->TargetInterface=BMAC[DstSlot].Interface;

	return ROUTE_RESULT_DONE;
}

/**************************************
* If this is an ARP packet...
**************************************/
int HandleARPPacket(int PacketSlot, ARPData* AData){
	PacketRec*		p;
	EthernetData*	EData;
	int				IPID;
	
#ifdef DEBUGPATH
	printf("In HandleARPPacket\n");
#endif

	p=&Globals.Packets[PacketSlot];

	/*pull out the ethernet header*/
	if (!GetDataByID(p->PacketSlot, EthernetDecoderID, (void**)&EData)){
#ifdef DEBUG
		printf("This is an Ethernet packet\n");
#endif	
		return ROUTE_RESULT_DROP;
	}

	/*check to see if this is a request or a reply*/
	if (ntohs(AData->Header->Operation)==ARP_OP_REQUEST){
	
#ifdef DEBUG
		printf("ARP Request from %s\n",inet_ntoa(*(struct in_addr*)AData->EthernetARPHeader->SenderIP));
#endif	

		if (FindMac(AData->EthernetARPHeader->SenderMac)==-1)
			AddMac(AData->EthernetARPHeader->SenderMac,	p->InterfaceNum);
	
		if (p->InterfaceNum==InternetIF){
#ifdef DEBUG
			printf("ARP Request from Internet.  Sending out Both\n");
#endif	
			EData->Header->DstMac[0]=0xFF;
			EData->Header->DstMac[1]=0xFF;
			EData->Header->DstMac[2]=0xFF;
			EData->Header->DstMac[3]=0xFF;
			EData->Header->DstMac[4]=0xFF;
			EData->Header->DstMac[5]=0xFF;

			p->TargetInterface=INTERFACE_BROADCAST;
			return ROUTE_RESULT_DONE;
		}else if (p->InterfaceNum==ProductionIF){
#ifdef DEBUG
			printf("ARP Request from Production.  Sending out Internet\n");
#endif	
			UpdateIP(*(int*)AData->EthernetARPHeader->SenderIP, 
			         AData->EthernetARPHeader->SenderMac,
					 BNS_PRODUCTION);
			p->TargetInterface=InternetIF;
			return ROUTE_RESULT_DONE;
		}else if (p->InterfaceNum==HoneyIF){
#ifdef DEBUG
			printf("ARP Request from Honeypot.  Mangling and send out Internet.\n");
#endif	
			IPID=UpdateIP(*(int*)AData->EthernetARPHeader->SenderIP, 
			         AData->EthernetARPHeader->SenderMac,
					 BNS_HONEY);
					 
			/*find the mac address of the production box with the same IP*/
			if (IPID==-1) return ROUTE_RESULT_DROP;
			if ( (BIP[IPID].ProdMac[0]==0) &&
			     (BIP[IPID].ProdMac[1]==0) &&
				 (BIP[IPID].ProdMac[2]==0) &&
				 (BIP[IPID].ProdMac[3]==0) &&
				 (BIP[IPID].ProdMac[4]==0) &&
				 (BIP[IPID].ProdMac[5]==0)
			){
#ifdef DEBUG
				printf("There is no production machine with this IP yet\n");
#endif			
				return ROUTE_RESULT_DROP;
			}else{
				/*change the src mac in ethernet header*/
				EData->Header->SrcMac[0]=BIP[IPID].ProdMac[0];
				EData->Header->SrcMac[1]=BIP[IPID].ProdMac[1];
				EData->Header->SrcMac[2]=BIP[IPID].ProdMac[2];
				EData->Header->SrcMac[3]=BIP[IPID].ProdMac[3];
				EData->Header->SrcMac[4]=BIP[IPID].ProdMac[4];
				EData->Header->SrcMac[5]=BIP[IPID].ProdMac[5];
				
				/*chg the src mac in arp header*/
				AData->EthernetARPHeader->SenderMac[0]=BIP[IPID].ProdMac[0];
				AData->EthernetARPHeader->SenderMac[1]=BIP[IPID].ProdMac[1];
				AData->EthernetARPHeader->SenderMac[2]=BIP[IPID].ProdMac[2];
				AData->EthernetARPHeader->SenderMac[3]=BIP[IPID].ProdMac[3];
				AData->EthernetARPHeader->SenderMac[4]=BIP[IPID].ProdMac[4];
				AData->EthernetARPHeader->SenderMac[5]=BIP[IPID].ProdMac[5];
				
				
				/*send it out*/
				p->TargetInterface=InternetIF;
				
				return ROUTE_RESULT_DONE;
			}
					 						
			return ROUTE_RESULT_DROP;			
		}
	}else if (ntohs(AData->Header->Operation)==ARP_OP_REPLY){

#ifdef DEBUG
		printf("ARP Reply from %s\n",inet_ntoa(*(struct in_addr*)AData->EthernetARPHeader->SenderIP));
#endif	

		if (FindMac(AData->EthernetARPHeader->SenderMac)==-1)
			AddMac(AData->EthernetARPHeader->SenderMac,	p->InterfaceNum);


		if (p->InterfaceNum==InternetIF){
#ifdef DEBUG
			printf("ARP Reply from Internet.  Sending out Both\n");
#endif	
			/*change the dest mac to the broadcast addr*/
			/*so it'll be seen by both machines*/
			EData->Header->DstMac[0]=0xFF;
			EData->Header->DstMac[1]=0xFF;
			EData->Header->DstMac[2]=0xFF;
			EData->Header->DstMac[3]=0xFF;
			EData->Header->DstMac[4]=0xFF;
			EData->Header->DstMac[5]=0xFF;
						
			p->TargetInterface=INTERFACE_BROADCAST;
			return ROUTE_RESULT_DONE;
		}else if (p->InterfaceNum==ProductionIF){
#ifdef DEBUG
			printf("ARP Reply from Production.  Sending out Internet\n");
#endif	
			/*make note of this mac address*/
			UpdateIP(*(unsigned int*)AData->EthernetARPHeader->SenderIP, 
				AData->EthernetARPHeader->SenderMac,
				BNS_PRODUCTION);

			p->TargetInterface=InternetIF;
			return ROUTE_RESULT_DONE;
		}else if (p->InterfaceNum==HoneyIF){
#ifdef DEBUG
			printf("ARP Reply from Honeypot.  Dropping.\n");
#endif	
			/*make note of this mac address*/
			UpdateIP(*(unsigned int*)AData->EthernetARPHeader->SenderIP, 
				AData->EthernetARPHeader->SenderMac,
				BNS_HONEY);
			
			return ROUTE_RESULT_DROP;			
		}
	}

	return ROUTE_RESULT_DROP;
}

/**************************************
* Apply BNS Routing
**************************************/
int RouteBNS(int PacketSlot){
	PacketRec*		p;
	IPData*			IData;
	ARPData*		AData;

#ifdef DEBUGPATH
	printf("In RouteMacFilter\n");
#endif
	
	p=&Globals.Packets[PacketSlot];
	
	if ( (p->InterfaceNum!=InternetIF) && 
	     (p->InterfaceNum!=ProductionIF) &&
		 (p->InterfaceNum!=HoneyIF)
	){
#ifdef DEBUG
		printf("We don't handle this interface\n");
#endif	
		return ROUTE_RESULT_CONTINUE;
	}
	
	if (GetDataByID(p->PacketSlot, IPDecoderID, (void**)&IData)){
#ifdef DEBUG1
		printf("This is an IP packet\n");
#endif	
		return HandleIPPacket(PacketSlot, IData);
	}else if (GetDataByID(p->PacketSlot, ARPDecoderID, (void**)&AData)){
#ifdef DEBUG1
		printf("This is an ARP packet\n");
#endif	
		return HandleARPPacket(PacketSlot, AData);
	}

	return ROUTE_RESULT_DROP;
}

/*********************************
* Turn on BNS Routing
**********************************/
int RouteBNSAddNode(int RouteID, char* Args){
	char*	c1;
	char*	c2;
	
#ifdef DEBUGPATH
	printf("In RouteBNSAddNode\n");
#endif

#ifdef DEBUG
	printf("AddNode was called with args %s\n", Args);
#endif	    

	if (!Args) return FALSE;
	
	/*pop off the first arg*/
	/*first arg is Internet Interface*/
	c1=Args;
	while ((*c1==' ') && (*c1!=0x00)) c1++;
	c2=strchr(Args, ',');
	if (!c2){
		printf("Expected \",\"\n");
		printf("Usage BNS(<InternetIF>, <ProductionIF>, <HoneyIF>, <BlackList>)\n");
		return FALSE;
	}
	*c2=0x00;
	c2++;

	InternetIF=GetInterfaceByName(c1);
	
	if (InternetIF==INTERFACE_NONE){
		printf("There is no interface %s\n",c1);
		return FALSE;
	}

#ifdef DEBUG
	printf("Internet Interface Set to %i(%s)\n",InternetIF, Globals.Interfaces[InternetIF].Name);
#endif	

	/*pop off the second arg*/
	/*second arg is Production Interface*/
	c1=c2;
	while ((*c1==' ') && (*c1!=0x00)) c1++;
	c2=strchr(c1, ',');
	if (!c2){
		printf("Expected \",\"\n");
		printf("Usage BNS(<InternetIF>, <ProductionIF>, <HoneyIF>, <BlackList>)\n");
		return FALSE;
	}
	*c2=0x00;
	c2++;

	ProductionIF=GetInterfaceByName(c1);
	
	if (ProductionIF==INTERFACE_NONE){
		printf("There is no interface %s\n",c1);
		return FALSE;
	}

#ifdef DEBUG
	printf("Production Interface Set to %i(%s)\n",ProductionIF, Globals.Interfaces[ProductionIF].Name);
#endif	
	

	/*pop off the third arg*/
	/*third arg is Honeypot Interface*/
	c1=c2;
	while ((*c1==' ') && (*c1!=0x00)) c1++;
	c2=strchr(c1, ',');
	if (!c2){
		printf("Expected \",\"\n");
		printf("Usage BNS(<InternetIF>, <ProductionIF>, <HoneyIF>, <BlackList>)\n");
		return FALSE;
	}

	*c2=0x00;
	c2++;
	HoneyIF=GetInterfaceByName(c1);
	
	if (HoneyIF==INTERFACE_NONE){
		printf("There is no interface %s\n",c1);
		return FALSE;
	}

#ifdef DEBUG
	printf("Honeypot Interface Set to %i(%s)\n",HoneyIF, Globals.Interfaces[HoneyIF].Name);
#endif	

	/*pop off the fourth arg*/
	/*third arg is the blacklist*/
	c1=c2;
	while ((*c1==' ') && (*c1!=0x00)) c1++;
	
	if (!AddIPRanges(BNSRerouteList, c1)){
		printf("Couldn't understand blacklist\n");
		return FALSE;
	}

#ifdef DEBUG
	printf("Added BlackList\n");
#endif	

	
	return TRUE;
}

/*********************************
* Set up everything to do bns routing
**********************************/
int InitRouteBNS(){
	int RouteID;
	
#ifdef DEBUGPATH
	printf("In InitBNS\n");
#endif	

	bzero(BIP, sizeof(BNS_IP) * MAX_BNS);
	BNSNumIP=0;
	bzero(BMAC, sizeof(BNS_MAC) * MAX_BNS);
	BNSNumMac=0;
	bzero(Notes, sizeof(BNSNote) * BNS_MAX_NOTES);
	ThisNote=0;
	
	if ( (RouteID=CreateRoute("BNS"))==ROUTE_NONE){
		printf("Couldn't create route BNS\n");
		return FALSE;
	}
	
	Globals.Routes[RouteID].RouteFunc=RouteBNS;
	Globals.Routes[RouteID].AddNode=RouteBNSAddNode;
	BNSRerouteList=InitNumList(LIST_TYPE_TIME);
		
	if ( (EthernetDecoderID=GetDecoderByName("Ethernet"))==DECODER_NONE){
		printf("Couldn't find the Ethernet Decoder\n");
		return FALSE;
	}

	if ( (ARPDecoderID=GetDecoderByName("ARP"))==DECODER_NONE){
		printf("Couldn't find the ARP Decoder\n");
		return FALSE;
	}

	if ( (IPDecoderID=GetDecoderByName("IP"))==DECODER_NONE){
		printf("Couldn't find the IP Decoder\n");
		return FALSE;
	}

	if ( (TCPDecoderID=GetDecoderByName("TCP"))==DECODER_NONE){
		printf("Couldn't find the TCP Decoder\n");
		return FALSE;
	}
	
	if ( (UDPDecoderID=GetDecoderByName("UDP"))==DECODER_NONE){
		printf("Couldn't find the UDP Decoder\n");
		return FALSE;
	}
	
	return TRUE;
}


