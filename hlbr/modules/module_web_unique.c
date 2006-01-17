#include "module_web_unique.h"

//#define DEBUG

#ifndef HAS_MYSQL
#include <stdio.h>
/**************************************
* dummy call for those builds that
* don't have MYSQL support
**************************************/
int InitModuleWebUnique(){
#ifdef DEBUGPATH
	printf("In InitModuleWebUnique (No MYSQL)\n");
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
#include "../decoders/decode_tcp.h"
#include "../engine/num_list.h"
#include <stdlib.h>

int					IPDecoderID;
int					TCPDecoderID;
extern GlobalVars	Globals;
MYSQL				sql;
NumList*			WUWebServers;
char				WUActive;
char 				WUDBase[512];
char				WUUser[512];
char				WUPass[512];
char				WUHost[512];
int					WUUseLogFile;
char				WULogFileName[512];

/****************************************
* Set up database access
****************************************/
int WebUniqueDbaseInit(){

#ifdef DEBUGPATH
	printf("In WebUniqueDbaseInit\n");
#endif

	mysql_init(&sql);
	if (!mysql_real_connect(&sql, WUHost, WUUser, WUPass, WUDBase, 0, NULL, 0)){
		printf("Failed to connect to database\n");
		return FALSE;
	}
	
	return TRUE;
}

/*******************************************
* Set some values on the module
*******************************************/
int WebUniqueParseArg (char* Arg){
#ifdef DEBUGPATH
	printf("In WebUniqueParseArg\n");
#endif

	while (*Arg==' ') Arg++;
	
	if (strncasecmp(Arg, "dbase=",6)==0){
		snprintf(WUDBase, 512, Arg+6);
#ifdef DEBUG	
		printf("Changing base name to \"%s\"\n",WUDBase);
#endif		
		return TRUE;
	} else if (strncasecmp(Arg, "user=",5)==0){
		snprintf(WUUser, 512, Arg+5);
#ifdef DEBUG	
		printf("Changing username to \"%s\"\n",WUUser);
#endif		
		return TRUE;
	} else if (strncasecmp(Arg, "host=",5)==0){
		snprintf(WUHost, 512, Arg+5);
#ifdef DEBUG	
		printf("Changing host to \"%s\"\n",WUHost);
#endif		
		return TRUE;		
	} else if (strncasecmp(Arg, "password=",9)==0){
		snprintf(WUPass, 512, Arg+9);
#ifdef DEBUG	
		printf("Changing password to \"%s\"\n",WUPass);
#endif		
		return TRUE;				
	} else if (strncasecmp(Arg, "logfile=",8)==0){
		snprintf(WULogFileName, 512, "%s%s",Globals.LogDir, Arg+8);
		WUUseLogFile=TRUE;
#ifdef DEBUG	
		printf("Changine LogFileName to \"%s\"\n",WULogFileName);
#endif		
		return TRUE;				
		
	} else if (strncasecmp(Arg, "servers=",8)==0){
#ifdef DEBUG	
		printf("Adding servers to list \"%s\"\n",Arg+8);
#endif		
		AddIPRanges(WUWebServers, Arg+8);
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
int WebUniqueLogMysql(struct in_addr DIP, struct in_addr SIP, struct timeval tv, char* request, char* raw, int raw_len){
	char		buff[65535];
	char		blob[(65535*2)+1];
	struct tm*	tm;
	FILE*		WUfp;
		
		
#ifdef DEBUGPATH
	printf("In WebUniqueLogMysql\n");
#endif		

	if (!WUActive){
#ifdef DEBUG
		printf("Activating module WebUnique\n");
#endif
		if (!WebUniqueDbaseInit()) return FALSE;
		WUActive=TRUE;		
	}
		
	snprintf(buff, 65535, "INSERT INTO urls(UnixTime, SrcAddrInt, SrcAddress, DstAddrInt, DstAddress,Request) VALUES(%li,%i,'%s',",(long)tv.tv_sec,ntohl(*(int*)&SIP), inet_ntoa(SIP));
	snprintf(buff+strlen(buff), 65535, "%i,'%s','%s');", ntohl(*(int*)&DIP), inet_ntoa(DIP), request);
	if (!mysql_real_query(&sql, buff, strlen(buff))){
		/*print out the log entry*/
		tm=localtime((time_t*)&tv.tv_sec);
#ifdef DEBUG		
		printf("%i/%i/%i %i:%i:%i %s->",tm->tm_mon+1, tm->tm_mday, 1900+tm->tm_year, tm->tm_hour,tm->tm_min,tm->tm_sec, inet_ntoa(SIP));
		printf("%s:%s\n",inet_ntoa(DIP),request);
#endif		
		
		if (WUUseLogFile){
			if ( (WUfp=fopen(WULogFileName, "a"))==NULL){
				printf("WEB_UNIQUE: Error opening \"%s\" for append\n",WULogFileName);
				/*keep loggin to the database anyway*/
				WUUseLogFile=FALSE;
			}
		
			fprintf(WUfp, "%i/%i/%i %i:%i:%i %s->",tm->tm_mon+1, tm->tm_mday, 1900+tm->tm_year, tm->tm_hour,tm->tm_min,tm->tm_sec, inet_ntoa(SIP));
			fprintf(WUfp, "%s:%s\n",inet_ntoa(DIP),request);
			
			fclose(WUfp);
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
* look for unique web requests
***************************************/
void WebUniqueFunc(int PacketSlot){
	char			buff[65535];
	int				i;
	IPData*			IData;
	TCPData*		TData;
	unsigned short	DPort;
	unsigned short	SPort;
	PacketRec*		p;
	
#ifdef DEBUGPATH
	printf("In WebUniqueFunc\n");
#endif	

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
#ifdef DEBUG
		printf("Couldn't get IP Header\n");
#endif	
		return;
	}

	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)){
#ifdef DEBUG
		printf("Couldn't get TCP Header\n");
#endif	
		return;
	}
	SPort=ntohs(TData->Header->source);
	DPort=ntohs(TData->Header->dest);
	
	if (DPort == 80){
		if (IsInList(WUWebServers, ntohl(IData->Header->daddr))){
			if ( 
				(strncasecmp(TData->Data, "GET", 3)==0) ||
				(strncasecmp(TData->Data, "PUT", 3)==0) ||
				(strncasecmp(TData->Data, "HEAD", 4)==0) ||
				(strncasecmp(TData->Data, "POST", 4)==0)
			){	

				if ((strncasecmp(TData->Data, "GET", 3)==0) || (strncasecmp(TData->Data, "PUT", 3)==0)){
					i=4;
				}else{
					i=5;
				}
				for (; i<TData->DataLen; i++){
					if ( (TData->Data[i]==' ') || (TData->Data[i]=='?') || (TData->Data[i]=='\n')){
						TData->Data[i]=0x00;
						break;
					}	
				}
#ifdef DEBUG				
				printf("_______________________\n");
				printf("%s:%u->", inet_ntoa(*(struct in_addr*)&IData->Header->saddr), SPort);
				printf("%s:%u\n", inet_ntoa(*(struct in_addr*)&IData->Header->daddr), DPort);
#endif				
				if (i<TData->DataLen){
#ifdef DEBUG				
					printf("%s\n",TData->Data);
#endif
					WebUniqueLogMysql(*(struct in_addr*)&IData->Header->daddr, *(struct in_addr*)&IData->Header->saddr, p->tv, TData->Data, p->RawPacket, p->PacketLen); 					
				}else{
					bzero(buff, 65535);
					memcpy(buff, TData->Data, TData->DataLen);
#ifdef DEBUG					
					printf("%s\n",buff);
#endif				
					WebUniqueLogMysql(*(struct in_addr*)&IData->Header->daddr, *(struct in_addr*)&IData->Header->saddr, p->tv,buff, p->RawPacket, p->PacketLen);	
				}
#ifdef DEBUG				
				printf("_______________________\n");
#endif				
			}	
		}
	}
}

/**************************************
* Set up the web unique logger
**************************************/
int InitModuleWebUnique(){
	int	ModuleID;
	
#ifdef DEBUGPATH
	printf("In InitModuleWebUnique\n");
#endif

	ModuleID=CreateModule("WebUnique");
	if(ModuleID==MODULE_NONE) return FALSE;
	
	if (!BindModuleToDecoder(ModuleID, "TCP")){
		printf("Failed to bind WebUnique Module to TCP\n");
		return FALSE;
	}
	
	Globals.Modules[ModuleID].ParseArg=WebUniqueParseArg;
	Globals.Modules[ModuleID].ModuleFunc=WebUniqueFunc;

	IPDecoderID=GetDecoderByName("IP");
	TCPDecoderID=GetDecoderByName("TCP");
	
	WUWebServers=InitNumList(LIST_TYPE_NORMAL);
	WUActive=FALSE;
	WUUseLogFile=FALSE;
	
	sprintf(WUDBase, "hogwash5");
	sprintf(WUUser, "hogwash");
	sprintf(WUPass, "password");
	sprintf(WUHost, "localhost");

	return TRUE;
}


#endif //HAS_MYSQL
