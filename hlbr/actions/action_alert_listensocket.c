#include "action_alert_listensocket.h"
#include <stdio.h>
#include "../engine/message.h"
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

//#define DEBUG

#define MAX_SOCKET_RETRIES	10

typedef struct action_listensocket_rec{
	unsigned short	Port;
	int 			SockFD;
	int 			ListenSocketFD[2];
} ActionLSocketRec;

#define MAX_REMOTES	10

typedef struct remote_connection{
	int		InUse;
	int		FD;
} RemoteConn;

extern GlobalVars	Globals;
RemoteConn			RCons[MAX_REMOTES];


/*****************************************
* push out the stats at regular intervals
*****************************************/
int ListenSocketTimerFunc(int TimerID, int Time, void* User){
	int					newfd;
	ActionLSocketRec*	data;
	DRecStat			s;

	//printf("Listen Socket timer called\n");

	data=(ActionLSocketRec*)User;
	newfd=data->ListenSocketFD[0];

	s.PreMagic=htonl(PREMAGIC);
	s.Type=LDATA_TYPE_STATISTICS;
	s.Len=sizeof(DRecStat);
	s.Len=htons(s.Len);
	s.Time=htonl(Time);
	s.PacketCount=htons(Globals.PacketsPerSec);
	s.TCPCount=htons(Globals.TCPPerSec);
	s.UDPCount=htons(Globals.UDPPerSec);

	write(newfd, &s, sizeof(s));

	return TRUE;	
}

/*********************************************/
/* Handle all the connections                */
/*********************************************/
void HandleClients(int sockfd, int readfd){
	fd_set 				rfds;
	struct timeval		tv;	
	int					retval;
	int					max;
	int					i;
	
	struct sockaddr_in	remote_addr;
	int					sin_size;
	
	char				buff[1024];

	bzero(RCons, sizeof(RemoteConn) * MAX_REMOTES);

	if (listen(sockfd, 10)==-1){
		printf("Can't listen\n");
		return;
	}

	/*main loop to handle stuff*/
	while (1){
		max=0;
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);
		if (sockfd>max) max=sockfd;
		FD_SET(readfd, &rfds);
		if (readfd>max) max=readfd;
		for (i=0;i<MAX_REMOTES;i++)
			if (RCons[i].InUse){
				FD_SET(RCons[i].FD, &rfds);
				if (RCons[i].FD>max) max=RCons[i].FD;
			}
		
		tv.tv_sec=10;
		tv.tv_usec=0;
		
		retval=select(max+1, &rfds, NULL, NULL, &tv);
		
		if (retval){
			for (i=0;i<MAX_REMOTES;i++){
				if (RCons[i].InUse)
				if (FD_ISSET(RCons[i].FD, &rfds)){
					close(RCons[i].FD);
					RCons[i].InUse=FALSE;
				}
			}
			if (FD_ISSET(readfd, &rfds)){
				sin_size=read(readfd, buff, 1024);
				for (i=0;i<MAX_REMOTES;i++){
					if (RCons[i].InUse)
					if (write(RCons[i].FD, buff, sin_size)<0){	
						printf("Failed to write to newfd\n");
					}
				}
			}		
			if (FD_ISSET(sockfd, &rfds)){
				sin_size=sizeof(struct sockaddr_in);
				for (i=0;i<MAX_REMOTES;i++){
					if (RCons[i].InUse==FALSE){
						RCons[i].FD=accept(sockfd, (struct sockaddr*)&remote_addr, &sin_size);
						if (RCons[i].FD==-1){
							printf("Failed to get new connection\n");
						}
						RCons[i].InUse=TRUE;
					
						write(RCons[i].FD, "200 HLBR data server ready\n", strlen("200 Hogwash data server ready\n"));
						break;
					}						
				}
			}
		}
	}
}

/******************************************
* Parse the args for this action
******************************************/
void* AlertListenSocketParseArgs(char* Args){
	ActionLSocketRec*	data;
	unsigned short		Port;
	struct sockaddr_in	listen_addr;
	
#ifdef DEBUGPATH
	printf("In AlertListenSocketParseArgs\n");
#endif

#ifdef DEBUG
	printf("Parsing args for action_alert_listensocket\n");
#endif	

	while (*Args==' ') Args++;
	
	Port=atoi(Args);
	if (Port==0xFFFF){
		printf("Invalid port number %s\n",Args);
		return NULL;
	}

	data=(ActionLSocketRec*)calloc(sizeof(ActionLSocketRec),1);
	data->Port=Port;
	
	data->SockFD=socket(AF_INET, SOCK_STREAM, 0);
	if (data->SockFD==-1){
		printf("Unable to create socket\n");
		return NULL;
	}
	
	bzero(&listen_addr, sizeof(struct sockaddr_in));
	listen_addr.sin_family=AF_INET;
	listen_addr.sin_port=htons(data->Port);
	listen_addr.sin_addr.s_addr=INADDR_ANY;
	
	if (bind(data->SockFD, (struct sockaddr*)&listen_addr, sizeof(struct sockaddr))==-1){
		printf("Failed to bind to port %u\n",data->Port);
		return NULL;
	}
	
	/*create a socket pair for inter process comm*/
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, data->ListenSocketFD)==-1){
		printf("Couldn't set up a socketpair\n");
		return NULL;
	}

	/*fork off for the handler*/
	if (fork()){
		HandleClients(data->SockFD, data->ListenSocketFD[1]);
		exit(0);
	}

	CreateTimer("AlertListenSocket Stats", 1, ListenSocketTimerFunc, (void*)data);
	
	return data;
}


/******************************************
* handle informational messages
******************************************/
int AlertListenSocketMessage(char* Message, void* Data){
	ActionLSocketRec*	data;
	
#ifdef DEBUGPATH
	printf("In AlertListenSocketMessage\n");
#endif

#ifdef DEBUG
	printf("Writing to the Alert Socket\n");
#endif

	if (!Data){
#ifdef DEBUG
		printf("I must have a socket to write to\n");
#endif	
		return FALSE;
	}
	
	data=(ActionLSocketRec*)Data;

	if (write(data->SockFD, Message, strlen(Message))==-1)
		return FALSE;
		
	return TRUE;
}

/******************************************
* write the alert message to the alert socket
******************************************/
int AlertListenSocketAction(int RuleNum, int PacketSlot, void* Data){
	char				Buff[1024];
	char				Buff2[1024];
	ActionLSocketRec*	data;
	PacketRec*			p;
	DRecAlert			alert;
	
#ifdef DEBUGPATH
	printf("In AlertListenSocketAction\n");
#endif

#ifdef DEBUG
	printf("Writing to the Alert Socket\n");
#endif

	if (!Data){
#ifdef DEBUG
		printf("I must have a socket to write to\n");
#endif	
		return FALSE;
	}
	
	p=&Globals.Packets[PacketSlot];
	data=(ActionLSocketRec*)Data;


	bzero(&alert, sizeof(DRecAlert));
	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, 1024)){
		printf("Couldn't alert header to packet\n");
		return FALSE;
	}
	
	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff2, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	snprintf(alert.Message, 1024, "%s %s\n",Buff, Buff2);
	
	alert.PreMagic=htonl(PREMAGIC);
	alert.Type=LDATA_TYPE_ALERT;
	alert.Len=sizeof(DRecAlert);
	alert.Len=htons(alert.Len);
	
	write(data->ListenSocketFD[0], &alert, sizeof(DRecAlert));
	
	return TRUE;
}

/********************************
* Set up the alert socket stuff
********************************/
int InitActionAlertListenSocket(){
	int ActionID;

#ifdef DEBUGPATH
	printf("In InitActionAlertListenSocket\n");
#endif

	ActionID=CreateAction("alert lsocket");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action alert lsocket\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=AlertListenSocketAction;
	Globals.ActionItems[ActionID].MessageFunc=AlertListenSocketMessage;
	Globals.ActionItems[ActionID].ParseArgs=AlertListenSocketParseArgs;

	return TRUE;
}
