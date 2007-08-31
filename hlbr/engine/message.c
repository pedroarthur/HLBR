#include "message.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../decoders/decode_ip.h"
#include "../decoders/decode_tcp.h"
#include "../decoders/decode_udp.h"
#include <netinet/in.h>
#include <arpa/inet.h>

//#define DEBUG

extern GlobalVars	Globals;

/***************************************************
* Make sense of a message string
***************************************************/
MessageItem* ParseMessageString(char* MString){
	MessageItem*	MI=NULL;
	MessageItem*	MThis=NULL;
	char*			CThis=NULL;
#ifdef DEBUGPATH
	printf("In ParseMessageString\n");
#endif
	
	CThis=MString;
	while (*CThis){
		if (!MI){
			MI=calloc(sizeof(MessageItem),1);
			MThis=MI;
		}else{
			MThis->Next=calloc(sizeof(MessageItem),1);
			MThis=MThis->Next;
		}
		if (*CThis=='%'){
			/*this might be a macro*/
			if (strncasecmp(CThis, "%sip",4)==0){
#ifdef DEBUG
				printf("SIP->");
#endif				
				CThis+=3;
				MThis->Type=MESSAGE_ITEM_SIP;				
			}else if (strncasecmp(CThis, "%dip",4)==0){
#ifdef DEBUG
				printf("DIP->");
#endif				
				CThis+=3;				
				MThis->Type=MESSAGE_ITEM_DIP;
			}else if (strncasecmp(CThis, "%sp",3)==0){
#ifdef DEBUG
				printf("SPort->");
#endif				
				CThis+=2;				
				MThis->Type=MESSAGE_ITEM_SPORT;				
			}else if (strncasecmp(CThis, "%dp",3)==0){
#ifdef DEBUG
				printf("DPort->");
#endif				
				CThis+=2;				
				MThis->Type=MESSAGE_ITEM_DPORT;
			}else if (strncasecmp(CThis, "%min",4)==0){
#ifdef DEBUG
				printf("Minute->");
#endif				
				CThis+=3;
				MThis->Type=MESSAGE_ITEM_MIN;
			}else if (strncasecmp(CThis, "%y",2)==0){
#ifdef DEBUG
				printf("Year->");
#endif				
				CThis+=1;				
				MThis->Type=MESSAGE_ITEM_YEAR;
			}else if (strncasecmp(CThis, "%m",2)==0){
#ifdef DEBUG
				printf("Month->");
#endif				
				CThis+=1;				
				MThis->Type=MESSAGE_ITEM_MONTH;
			}else if (strncasecmp(CThis, "%d",2)==0){
#ifdef DEBUG
				printf("Day->");
#endif				
				CThis+=1;				
				MThis->Type=MESSAGE_ITEM_DAY;
			}else if (strncasecmp(CThis, "%h",2)==0){
#ifdef DEBUG
				printf("Hour->");
#endif				
				CThis+=1;				
				MThis->Type=MESSAGE_ITEM_HOUR;
			}else if (strncasecmp(CThis, "%s",2)==0){
#ifdef DEBUG
				printf("Second->");
#endif				
				CThis+=1;				
				MThis->Type=MESSAGE_ITEM_SEC;
			}else if (strncasecmp(CThis, "%usec",5)==0){
#ifdef DEBUG
				printf("USec->");
#endif				
				CThis+=4;
				MThis->Type=MESSAGE_ITEM_USEC;
			}else if (strncasecmp(CThis, "%pn",3)==0){
#ifdef DEBUG
				printf("PacketNum->");
#endif				
				CThis+=2;
				MThis->Type=MESSAGE_ITEM_PACKET_NUM;				
			}else if (strncasecmp(CThis, "%ac",3)==0){
#ifdef DEBUG
				printf("AlertCount->");
#endif				
				CThis+=2;
				MThis->Type=MESSAGE_ITEM_ALERT_COUNT;
			}else{
				/*we don't recognise this, assume text*/
#ifdef DEBUG
				printf("\"%c\"->",*CThis);
#endif							
				MThis->Value='_';
				MThis->Type=MESSAGE_ITEM_CHAR;
			}
		}else{
			/*Add this to the text stuff*/
#ifdef DEBUG
			printf("\"%c\"->",*CThis);
#endif			
			MThis->Value=*CThis;
			MThis->Type=MESSAGE_ITEM_CHAR;
		}
		CThis++;
	}
	
#ifdef DEBUG
	printf("\n");
#endif	

	return MI;
}

/***************************************************
* Free a message 
***************************************************/
void FreeMessage(MessageItem* MItem){
	MessageItem*	m;
	MessageItem*	del;
#ifdef DEBUGPATH
	printf("In FreeMessage\n");
#endif

	m=MItem;
	while (m){
		del=m;
		m=m->Next;
		free(del);
		del=NULL;
	}
}

/***************************************************
* Fill in the message string from the packet
***************************************************/
int ApplyMessage(MessageItem* MItem, int PacketSlot, char* Buff, int BuffLen){
	MessageItem*	MThis;
	int				Total;
	IPData*			ip_data=NULL;
	TCPData*		tcp_data=NULL;
	UDPData*		udp_data=NULL;
	PacketRec*		p;
	struct tm*		tm;
	
#ifdef DEBUGPATH
	printf("In ApplyMessage\n");
#endif

	if (!MItem){
		Buff[0]=0x00;
		return FALSE;
	}

	p=&Globals.Packets[PacketSlot];
	tm=localtime(&p->tv.tv_sec);

	Total=0;
	MThis=MItem;
	while (MThis){
		switch (MThis->Type){
		case MESSAGE_ITEM_SIP:
			if (!ip_data){
				if (!GetDataByID(PacketSlot, GetDecoderByName("IP"), (void**)&ip_data)){
					snprintf(Buff+Total, BuffLen-Total, "???.???.???.???");
					Total+=strlen("???.???.???.???");
					break;
				}
			}
			
			snprintf(Buff+Total, BuffLen-Total, "%s", inet_ntoa(*(struct in_addr*)&ip_data->Header->saddr));
			Total=strlen(Buff);
			break;
		case MESSAGE_ITEM_DIP:
			if (!ip_data){
				if (!GetDataByID(PacketSlot, GetDecoderByName("IP"), (void**)&ip_data)){
					snprintf(Buff+Total, BuffLen-Total, "???.???.???.???");
					Total+=strlen("???.???.???.???");
					break;
				}
			}
			
			snprintf(Buff+Total, BuffLen-Total, "%s", inet_ntoa(*(struct in_addr*)&ip_data->Header->daddr));
			Total=strlen(Buff);			
			break;
		case MESSAGE_ITEM_SPORT:
			/*get for both TCP and UDP*/
			if (ip_data){
				if (ip_data->Header->protocol==IP_PROTO_TCP){
					if (!GetDataByID(PacketSlot, GetDecoderByName("TCP"), (void**)&tcp_data)){
						snprintf(Buff+Total, BuffLen-Total, "??");
						Total+=strlen("??");
						break;
					}
			
					snprintf(Buff+Total, BuffLen-Total, "%u", ntohs(tcp_data->Header->source));
					Total=strlen(Buff);			
					break;
				}else if (ip_data->Header->protocol==IP_PROTO_UDP){
					if (!GetDataByID(PacketSlot, GetDecoderByName("UDP"), (void**)&udp_data)){
						snprintf(Buff+Total, BuffLen-Total, "??");
						Total+=strlen("??");
						break;
					}
			
					snprintf(Buff+Total, BuffLen-Total, "%u", ntohs(udp_data->Header->source));
					Total=strlen(Buff);			
					break;										
				}else{
					snprintf(Buff+Total, BuffLen-Total, "??");
					Total+=strlen("??");
					break;		
				}
			}else{
				snprintf(Buff+Total, BuffLen-Total, "??");
				Total+=strlen("??");
				break;		
			}
		case MESSAGE_ITEM_DPORT:
			/*get for both TCP and UDP*/
			if (!ip_data){	
				snprintf(Buff+Total, BuffLen-Total, "??");
				Total+=strlen("??");
				break;		
			}
			
			if (ip_data->Header->protocol==IP_PROTO_TCP){
				if (!GetDataByID(PacketSlot, GetDecoderByName("TCP"), (void**)&tcp_data)){
					snprintf(Buff+Total, BuffLen-Total, "??");
					Total+=strlen("??");
					break;
				}
			
				snprintf(Buff+Total, BuffLen-Total, "%u", ntohs(tcp_data->Header->dest));
				Total=strlen(Buff);
				break;						
			}else if (ip_data->Header->protocol==IP_PROTO_UDP){
				if (!GetDataByID(PacketSlot, GetDecoderByName("UDP"), (void**)&udp_data)){
					snprintf(Buff+Total, BuffLen-Total, "??");
					Total+=strlen("??");
					break;
				}
			
				snprintf(Buff+Total, BuffLen-Total, "%u", ntohs(udp_data->Header->dest));				Total=strlen(Buff);			
				break;										
			}else{
				snprintf(Buff+Total, BuffLen-Total, "??");
				Total+=strlen("??");
				break;		
			}			
		case MESSAGE_ITEM_CHAR:
			snprintf(Buff+Total, BuffLen-Total, "%c",MThis->Value);
			Total+=1;
			break;
		case MESSAGE_ITEM_YEAR:
			snprintf(Buff+Total, BuffLen-Total, "%04i",tm->tm_year+1900);
			Total+=4;
			break;			
		case MESSAGE_ITEM_MONTH:
			snprintf(Buff+Total, BuffLen-Total, "%02i",tm->tm_mon+1);
			Total+=2;
			break;
		case MESSAGE_ITEM_DAY:
			snprintf(Buff+Total, BuffLen-Total, "%02i",tm->tm_mday);
			Total+=2;
			break;
		case MESSAGE_ITEM_HOUR:
			snprintf(Buff+Total, BuffLen-Total, "%02i",tm->tm_hour);
			Total+=2;
			break;
		case MESSAGE_ITEM_MIN:
			snprintf(Buff+Total, BuffLen-Total, "%02i",tm->tm_min);
			Total+=2;
			break;
		case MESSAGE_ITEM_SEC:
			snprintf(Buff+Total, BuffLen-Total, "%02i",tm->tm_sec);
			Total+=2;
			break;
		case MESSAGE_ITEM_USEC:
			snprintf(Buff+Total, BuffLen-Total, "%04li",p->tv.tv_sec);
			Total+=4;
			break;
		case MESSAGE_ITEM_PACKET_NUM:
			snprintf(Buff+Total, BuffLen-Total, "%08u",p->PacketNum);
			Total+=8;
			break;
		case MESSAGE_ITEM_ALERT_COUNT:
			snprintf(Buff+Total, BuffLen-Total, "%08u",Globals.AlertCount);
			Total+=8;
			break;			
		default:
#ifdef DEBUG
			printf("I don't know how to handle that message type (%i)\n", MThis->Type);
#endif	
			break;
		}
		MThis=MThis->Next;
	}

	return TRUE;
}
