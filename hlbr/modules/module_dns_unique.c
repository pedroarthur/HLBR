#include "module_dns_unique.h"

//#define DEBUG

#ifndef HAS_MYSQL
#include <stdio.h>
/**************************************
* dummy call for those builds that
* don't have MYSQL support
**************************************/
int InitModuleDNSUnique(){
#ifdef DEBUGPATH
	printf("In InitModuleDNSUnique (No MYSQL)\n");
#endif

#ifdef DEBUG
	printf("There is no MYSQL support\n");
#endif	

	return TRUE;
}

#else

#include <mysql/mysql.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../decoders/decode.h"
#include <stdio.h>
#include "../decoders/decode_ip.h"
#include "../decoders/decode_udp.h"
#include "../decoders/decode_dns.h"
#include "../engine/num_list.h"
#include <stdlib.h>

int					IPDecoderID;
int					UDPDecoderID;
int					DNSDecoderID;
extern GlobalVars	Globals;
MYSQL				sql;
NumList*			DUDNSServers;
char				DUActive;
char 				DUDBase[512];
char				DUUser[512];
char				DUPass[512];
char				DUHost[512];
int					DUUseLogFile;
char				DULogFileName[512];

/****************************************
* Set up database access
****************************************/
int DNSUniqueDbaseInit(){

#ifdef DEBUGPATH
	printf("In DNSUniqueDbaseInit\n");
#endif

	mysql_init(&sql);
	if (!mysql_real_connect(&sql, DUHost, DUUser, DUPass, DUDBase, 0, NULL, 0)){
		printf("Failed to connect to database\n");
		return FALSE;
	}
	
	return TRUE;
}

/*******************************************
* Set some values on the module
*******************************************/
int DNSUniqueParseArg (char* Arg){
#ifdef DEBUGPATH
	printf("In DNSUniqueParseArg\n");
#endif

	while (*Arg==' ') Arg++;
	
	if (strncasecmp(Arg, "dbase=",6)==0){
		snprintf(DUDBase, 512, Arg+6);
#ifdef DEBUG	
		printf("Changing base name to \"%s\"\n",DUDBase);
#endif		
		return TRUE;
	} else if (strncasecmp(Arg, "user=",5)==0){
		snprintf(DUUser, 512, Arg+5);
#ifdef DEBUG	
		printf("Changing username to \"%s\"\n",DUUser);
#endif		
		return TRUE;
	} else if (strncasecmp(Arg, "host=",5)==0){
		snprintf(DUHost, 512, Arg+5);
#ifdef DEBUG	
		printf("Changing host to \"%s\"\n",DUHost);
#endif		
		return TRUE;		
	} else if (strncasecmp(Arg, "password=",9)==0){
		snprintf(DUPass, 512, Arg+9);
#ifdef DEBUG	
		printf("Changing password to \"%s\"\n",DUPass);
#endif		
		return TRUE;				
	} else if (strncasecmp(Arg, "logfile=",8)==0){
		snprintf(DULogFileName, 512, "%s%s",Globals.LogDir, Arg+8);
		DUUseLogFile=TRUE;
#ifdef DEBUG	
		printf("Changine LogFileName to \"%s\"\n",DULogFileName);
#endif		
		return TRUE;				
		
	} else if (strncasecmp(Arg, "servers=",8)==0){
#ifdef DEBUG	
		printf("Adding servers to list \"%s\"\n",Arg+8);
#endif		
		AddIPRanges(DUDNSServers, Arg+8);
		return TRUE;						
	}else{
		printf("I don't understand \"%s\"\n", Arg);
		return FALSE;
	}

	return TRUE;
}


/***********************************
* Write out this entry into MYSQL
***********************************/
int DNSUniqueLogMysql(struct in_addr DIP, struct in_addr SIP, struct timeval tv, char* request, char* raw, int raw_len){
	char		buff[65535];
	char		blob[(65535*2)+1];
	struct tm*	tm;
	FILE*		DUfp;
		
		
#ifdef DEBUGPATH
	printf("In DNSUniqueLogMysql\n");
#endif		

	if (!DUActive){
#ifdef DEBUG
		printf("Activating module DNSUnique\n");
#endif
		if (!DNSUniqueDbaseInit()) return FALSE;
		DUActive=TRUE;		
	}
		
	snprintf(buff, 65535, "INSERT INTO dns(UnixTime, SrcAddrInt, SrcAddress, DstAddrInt, DstAddress,Request1) VALUES(%li,%i,'%s',",(long)tv.tv_sec,ntohl(*(int*)&SIP), inet_ntoa(SIP));
	snprintf(buff+strlen(buff), 65535, "%i,'%s','%s');", ntohl(*(int*)&DIP), inet_ntoa(DIP), request);
	if (!mysql_real_query(&sql, buff, strlen(buff))){
		/*print out the log entry*/
		tm=localtime((time_t*)&tv.tv_sec);
#ifdef DEBUG		
		printf("%i/%i/%i %i:%i:%i %s->",tm->tm_mon+1, tm->tm_mday, 1900+tm->tm_year, tm->tm_hour,tm->tm_min,tm->tm_sec, inet_ntoa(SIP));
		printf("%s:%s\n",inet_ntoa(DIP),request);
#endif		
		
		if (DUUseLogFile){
			if ( (DUfp=fopen(DULogFileName, "a"))==NULL){
				printf("DNS_UNIQUE: Error opening \"%s\" for append\n",DULogFileName);
				/*keep loggin to the database anyway*/
				DUUseLogFile=FALSE;
			}
		
			fprintf(DUfp, "%i/%i/%i %i:%i:%i %s->",tm->tm_mon+1, tm->tm_mday, 1900+tm->tm_year, tm->tm_hour,tm->tm_min,tm->tm_sec, inet_ntoa(SIP));
			fprintf(DUfp, "%s:%s\n",inet_ntoa(DIP),request);
			
			fclose(DUfp);
		}
		
		/*now record the raw packet*/
		mysql_real_escape_string(&sql, blob, raw, raw_len);
		snprintf(buff, 65535, "INSERT INTO raw_packet(UrlID, Packet) VALUES(%llu, '%s');",mysql_insert_id(&sql),blob);
		if (mysql_real_query(&sql, buff, strlen(buff))){
			printf("Query failed: %s\n", buff);
		}
	}

	return TRUE;
}

/***************************************
* look for unique dns requests
***************************************/
void DNSUniqueFunc(int PacketSlot){
	IPData*			IData;
	UDPData*		TData;
	DNSData*		DData;
	unsigned short	DPort;
	unsigned short	SPort;
	PacketRec*		p;
	
#ifdef DEBUGPATH
	printf("In DNSUniqueFunc\n");
#endif	

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
#ifdef DEBUG
		printf("Couldn't get IP Header\n");
#endif	
		return;
	}

	if (!GetDataByID(PacketSlot, UDPDecoderID, (void**)&TData)){
#ifdef DEBUG
		printf("Couldn't get UDP Header\n");
#endif	
		return;
	}
	
	if (!GetDataByID(PacketSlot, DNSDecoderID, (void**)&DData)){
#ifdef DEBUG
		printf("Couldn't get UDP Header\n");
#endif	
		return;
	}

	
	SPort=ntohs(TData->Header->source);
	DPort=ntohs(TData->Header->dest);
	
#ifdef DEBUG				
	printf("_______________________\n");
	printf("%s:%u->", inet_ntoa(*(struct in_addr*)&IData->Header->saddr), SPort);
	printf("%s:%u\n", inet_ntoa(*(struct in_addr*)&IData->Header->daddr), DPort);
#endif				

	if (!(DData->Header1->Flags & DNS_FLAG_QUERY)){
#ifdef DEBUG
		printf("Is a Query\n");
#endif	
		if (IsInList(DUDNSServers, ntohl(IData->Header->daddr))){
#ifdef DEBUG
			printf("Is in list of dns servers\n");
#endif	
			DNSUniqueLogMysql(*(struct in_addr*)&IData->Header->daddr, *(struct in_addr*)&IData->Header->saddr, p->tv, DData->Q[0].Query, p->RawPacket, p->PacketLen); 					
		}else{
#ifdef DEBUG
			printf("Wasn't in list of dns servers\n");
#endif	
		}
	}else{
#ifdef DEBUG
		printf("Wasn't a query\n");
#endif	
	}
}

/**************************************
* Set up the DNS unique logger
**************************************/
int InitModuleDNSUnique(){
	int	ModuleID;
	
#ifdef DEBUGPATH
	printf("In InitModuleDNSUnique\n");
#endif

	ModuleID=CreateModule("DNSUnique");
	if(ModuleID==MODULE_NONE) return FALSE;
	
	if (!BindModuleToDecoder(ModuleID, "DNS")){
		printf("Failed to bind DNSUnique Module to DNS\n");
		return FALSE;
	}
	
	Globals.Modules[ModuleID].ParseArg=DNSUniqueParseArg;
	Globals.Modules[ModuleID].ModuleFunc=DNSUniqueFunc;

	IPDecoderID=GetDecoderByName("IP");
	UDPDecoderID=GetDecoderByName("UDP");
	DNSDecoderID=GetDecoderByName("DNS");
	
	DUDNSServers=InitNumList(LIST_TYPE_NORMAL);
	DUActive=FALSE;
	DUUseLogFile=FALSE;
	
	sprintf(DUDBase, "hogwash5");
	sprintf(DUUser, "hogwash");
	sprintf(DUPass, "password");
	sprintf(DUHost, "localhost");

	return TRUE;
}


#endif //HAS_MYSQL
