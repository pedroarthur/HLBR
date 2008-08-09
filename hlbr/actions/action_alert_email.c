/********************************************
* TODO: Add all the thread locking and stuff
* TODO: actually look for error codes
*********************************************/

#include "action_alert_email.h"
#include <stdio.h>
#include "../engine/message.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

//#define DEBUG

extern GlobalVars	Globals;

typedef struct alert_email_data{
	char 	Host[MAX_EMAIL_ARG_LEN];
	char	From[MAX_EMAIL_ARG_LEN];
	char	To[MAX_EMAIL_ARG_LEN];
	char	Subject[MAX_EMAIL_ARG_LEN];
	char* 	Message;
} EMailData;

// Until today, a useless Mutex...
//pthread_mutex_t	EMailMutex=PTHREAD_MUTEX_INITIALIZER;

/******************************************
* Send off an e-mail 
******************************************/
void* EMailMessageReal(void* data){
	EMailData*			Data;
	struct hostent*		he;
	struct sockaddr_in	host_addr;
	int					sockfd;
	char				Buff[MAX_EMAIL_ARG_LEN+128];

	DEBUGPATH;

	if (!data) return NULL;
	Data=(EMailData*)data;

	if ( (he=gethostbyname(Data->Host)) ==NULL){
		printf("Couldn't resolve \"%s\"\n",Data->Host);
		goto FreeMe;
	}
	
	if ( (sockfd=socket(AF_INET, SOCK_STREAM,0)) ==-1){
		printf("Couldn't create socket\n");
		goto FreeMe;
	}
	
	bzero(&host_addr, sizeof(struct sockaddr_in));
	host_addr.sin_family=AF_INET;
	host_addr.sin_port=htons(25);
	host_addr.sin_addr=*((struct in_addr*)he->h_addr);
	
	if (connect(sockfd, (struct sockaddr*)&host_addr, sizeof(struct sockaddr))==-1){
		printf("Counldn't connect to %s port 25\n", Data->Host);
		goto FreeMe;
	}
	
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "Mail From: %s\n", Data->From);
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send Mail From\n");
		goto FreeMe;
	}
	sleep(1);
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "Rcpt To: %s\n", Data->To);
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send Rcpt To\n");
		goto FreeMe;
	}
	sleep(1);
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "data\n");
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send data\n");
		goto FreeMe;
	}
	sleep(1);
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "Subject: %s\n\n", Data->Subject);
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send Subject\n");
		goto FreeMe;
	}
	sleep(1);
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "%s\n", Data->Message);
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send Message\n");
		goto FreeMe;
	}
	sleep(1);
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "\n.\n");
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send Terminator\n");
		goto FreeMe;
	}
	sleep(1);
	snprintf(Buff, MAX_EMAIL_ARG_LEN+128, "quit\n");
	if (!send(sockfd, Buff, strlen(Buff), 0)==-1){
		printf("Failed to send quit\n");
		goto FreeMe;
	}
	sleep(1);


	close(sockfd);
	
FreeMe:
	if (Data->Message) free(Data->Message);
	Data->Message=NULL;

	return (void*)TRUE;
}


/****************************************
* Send off the e-mail.  Fork if we're no
* using threads. otherwise, spawn a thread
*****************************************/
void EMailMessage(EMailData* data, char* Message){
	pthread_t	email_thread;
	
	DEBUGPATH;

	/*Make a copy of the Message Buffer*/
	data->Message=malloc(1024);
	snprintf(data->Message, 1024, "%s", Message);

	if (!Globals.UseThreads){
		if (!fork()){
			EMailMessageReal(data);
			exit(0);
		}	
	}else{	
		pthread_create(&email_thread, NULL, EMailMessageReal, data);
		pthread_detach(email_thread);
	}

}

/*******************************************
* Get the specifics from the command line
*
* Format (Host, From, To, Subject)
*******************************************/
void* AlertEMailParseArgs(char* Args){
	EMailData*		data;
	char*			c1;
	char*			c2;

	DEBUGPATH;

	data=(EMailData*)calloc(sizeof(EMailData),1);

	c1=Args;
	while ( (*c1) && (*c1==' ') ) c1++;
	if (!*c1){
		printf("Expected (Host, From, To, Subject)\n");
		free(data);
		return NULL;
	}
	
	c2=strchr(c1, ',');
	if (!c2){
		printf("Expected \",\"\n");
		free(data);
		return NULL;
	}
	*c2=0x00;
	
	snprintf(data->Host, MAX_EMAIL_ARG_LEN, "%s", c1);
#ifdef DEBUG
	printf("Setting Host to \"%s\"\n",data->Host);
#endif	

	c1=c2+1;
	while ( (*c1) && (*c1==' ') ) c1++;
	if (!*c1){
		printf("Expected (Host, From, To, Subject)\n");
		free(data);
		return NULL;
	}
	
	c2=strchr(c1, ',');
	if (!c2){
		printf("Expected \",\"\n");
		free(data);
		return NULL;
	}
	*c2=0x00;

	snprintf(data->From, MAX_EMAIL_ARG_LEN, "%s", c1);
#ifdef DEBUG
	printf("Setting From to \"%s\"\n",data->From);
#endif	

	c1=c2+1;
	while ( (*c1) && (*c1==' ') ) c1++;
	if (!*c1){
		printf("Expected (Host, From, To, Subject)\n");
		free(data);
		return NULL;
	}
	
	c2=strchr(c1, ',');
	if (!c2){
		printf("Expected \",\"\n");
		free(data);
		return NULL;
	}
	*c2=0x00;

	snprintf(data->To, MAX_EMAIL_ARG_LEN, "%s", c1);
#ifdef DEBUG
	printf("Setting To to \"%s\"\n",data->To);
#endif	

	c1=c2+1;
	while ( (*c1) && (*c1==' ') ) c1++;
	if (!*c1){
		printf("Expected (Host, From, To, Subject)\n");
		free(data);
		return NULL;
	}
	
	snprintf(data->Subject, MAX_EMAIL_ARG_LEN, "%s", c1);
#ifdef DEBUG
	printf("Setting Subject to \"%s\"\n",data->Subject);
#endif	

	return data;
}

/******************************************
* handle info messages
******************************************/
int AlertEMailMessage(char* Message, void* Data){

  DEBUGPATH;

#ifdef DEBUG
	printf("Emailing %s\n",Message);
#endif

	EMailMessage(Data, Message);
	
	return TRUE;
}

/******************************************
* write the alert message to the email
******************************************/
int AlertEMailAction(int RuleNum, int PacketSlot, void* Data){
	char		Buff[1024];
	PacketRec*	p;
	EMailData*	data;
	
	DEBUGPATH;

	if (!Data) return FALSE;
	data=(EMailData*)Data;

	p=&Globals.Packets[PacketSlot];

	if (!ApplyMessage(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)){
		printf("Couldn't apply message to packet\n");
		return FALSE;
	}

#ifdef DEBUG
	printf("Sending email with message %s\n",Buff);
#endif
	
	EMailMessage(data, Buff);
	
	return TRUE;
}

/********************************
* Set up the alert email stuff
********************************/
int InitActionAlertEMail(){
	int ActionID;

	DEBUGPATH;

	ActionID=CreateAction("email");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action alert email\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=AlertEMailAction;
	Globals.ActionItems[ActionID].MessageFunc=AlertEMailMessage;
	Globals.ActionItems[ActionID].ParseArgs=AlertEMailParseArgs;

	return TRUE;
}
