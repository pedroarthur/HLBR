#include "action_alert_socket.h"
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

typedef struct action_socket_rec{
	unsigned int	IP;
	unsigned short	Port;
	int 			SockFD;
	int				Retries;
} ActionSocketRec;

extern GlobalVars	Globals;


/******************************************
* Connect to the socket
* return TRUE on success
******************************************/
int AlertSocketConnect(ActionSocketRec* SR){
	struct sockaddr_in	target;
	
	if ( (SR->SockFD=socket(AF_INET, SOCK_STREAM, 0)) == -1){
		printf("Couldn't create socket\n");
		SR->Retries++;
		return FALSE;
	}

	bzero(&target, sizeof(target));
	target.sin_family=AF_INET;
	target.sin_port=SR->Port;
	target.sin_addr=*(struct in_addr*)&SR->IP;
	
	if (connect(SR->SockFD, (struct sockaddr*)&target, sizeof(struct sockaddr))==-1){
		printf("Couldn't connect to host\n");
		SR->Retries++;
		return FALSE;
	}	
	
	return TRUE;
}

/******************************************
* Parse the args for this action
******************************************/
void* AlertSocketParseArgs(char* Args){
	ActionSocketRec*	data;
	unsigned int		IP;
	unsigned short		Port;
	char*				c;
	struct hostent*		he;
	struct sockaddr_in	target;
	
#ifdef DEBUGPATH
	printf("In AlertSocketParseArgs\n");
#endif

#ifdef DEBUG
	printf("Parsing args for action_alert_socket\n");
#endif	

	while (*Args==' ') Args++;
	
	c=strchr(Args, ':');
	if (!c){
		printf("Usage: response=alert socket(IP:Port)\n");
		return NULL;
	}

	*c=0x00;
	c++;
	
	if ( (he=gethostbyname(Args))==NULL){
		printf("Couldn't resolve %s\n", Args);
		return NULL;
	}
	
	IP=*(unsigned int*)he->h_addr;

#ifdef DEBUG
	printf("Connecting to %s\n",inet_ntoa(*(struct in_addr*)&IP));
#endif
	
	Port=atoi(c);
	if (!Port){
		printf("Invalid port number %s\n",c);
		return NULL;
	}
	Port=htons(Port);

	data=(ActionSocketRec*)calloc(sizeof(ActionSocketRec),1);
	data->IP=IP;
	data->Port=Port;

	if (!AlertSocketConnect(data)){
		printf("Couldn't connect to %s:%s\n",Args, c);
		return NULL;
	}
	
	return data;
}


/******************************************
* handle informational messages
******************************************/
int AlertSocketMessage(char* Message, void* Data){
	ActionSocketRec*	data;
	
#ifdef DEBUGPATH
	printf("In AlsertSocketMessage\n");
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
	
	data=(ActionSocketRec*)Data;

	if (data->Retries>MAX_SOCKET_RETRIES) return FALSE;

	if (write(data->SockFD, Message, strlen(Message))==-1){
		if (AlertSocketConnect(data))
		write(data->SockFD, Message, strlen(Message));
	}
	if (write(data->SockFD, "\n", 1)==-1){
		if (AlertSocketConnect(data))
		write(data->SockFD, "\n", 1);
	}
		
	return TRUE;
}

/******************************************
* write the alert message to the alert socket
******************************************/
int AlertSocketAction(int RuleNum, int PacketSlot, void* Data){
	char				Buff[1024];
	ActionSocketRec*	data;
	PacketRec*			p;
	
#ifdef DEBUGPATH
	printf("In AlsertSocketAction\n");
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
	data=(ActionSocketRec*)Data;

	if (data->Retries>MAX_SOCKET_RETRIES) return FALSE;

	if (!ApplyMessage(Globals.AlertHeader, PacketSlot, Buff, 1024)){
		printf("Couldn't alert header to packet\n");
		return FALSE;
	}

	if (write(data->SockFD, Buff, strlen(Buff))==-1){
		if (AlertSocketConnect(data))
		write(data->SockFD, Buff, strlen(Buff));
	}
	if (write(data->SockFD, " ", 1)==-1){
		if (AlertSocketConnect(data))
		write(data->SockFD, " ", 1);
	}

	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

	if (write(data->SockFD, Buff, strlen(Buff))==-1){
		if (AlertSocketConnect(data))
		write(data->SockFD, Buff, strlen(Buff));
	}

	if (write(data->SockFD, "\n", 1)==-1){
		if (AlertSocketConnect(data))
		write(data->SockFD, "\n", 1);
	}
	
	return TRUE;
}

/********************************
* Set up the alert socket stuff
********************************/
int InitActionAlertSocket(){
	int ActionID;

#ifdef DEBUGPATH
	printf("In InitActionAlertSocket\n");
#endif

	ActionID=CreateAction("alert socket");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action alert socket\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=AlertSocketAction;
	Globals.ActionItems[ActionID].MessageFunc=AlertSocketMessage;
	Globals.ActionItems[ActionID].ParseArgs=AlertSocketParseArgs;

	return TRUE;
}
