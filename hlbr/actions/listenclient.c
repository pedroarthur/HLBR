/*************************************
* Sample client for talking to a
* socket listener
*************************************/
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include "action_alert_listensocket.h"

/************************************
* The one and only main
************************************/
int main(int argc, char**argv){
	unsigned char		Buff[1024];
	struct hostent*		he;
	int					sockfd, numbytes;
	struct sockaddr_in	their_addr;
	unsigned short		port;
	DRec*				drec;
	struct tm*			tm;

	if (argc != 3) {
		printf("usage: %s hostname port\n", argv[0]);
		exit(1);
	}

	if ((he=gethostbyname(argv[1])) == NULL) {  // get the host info 
		printf("Failed to resolve %s\n",argv[1]);
		exit(1);
	}

	port=atoi(argv[2]);
	if (port==0xFFFF){
		printf("Invalid port number %s\n",argv[2]);
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Failed to create socket\n");
		exit(1);
	}

	their_addr.sin_family = AF_INET;    // host byte order 
	their_addr.sin_port = htons(port);  // short, network byte order 
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(their_addr.sin_zero), '\0', 8);  // zero the rest of the struct 

	if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
		printf("Failed to connect to %s:%u\n",argv[1], port);
		exit(1);
	}

	if ((numbytes=recv(sockfd, Buff, 1024-1, 0)) == -1) {
		printf("Failed recieve banner\n");
		exit(1);
	}

	if (strncmp("200", Buff, 3)!=0){
		printf("Expected 200 Hello\n");
		exit(1);
	}

	/*loop through and read the messages*/
	while (1){
		bzero(Buff, 1024);
		numbytes=recv(sockfd, &Buff, sizeof(DRec),0);
		if (numbytes!=sizeof(DRec)){
			printf("Unexpected data %i\n",numbytes);
			exit(1);
		}
		drec=(DRec*)Buff;
		printf("From the header:\n");
		printf("  PreMagic %p\n", ntohl(drec->PreMagic));
		printf("  Type %u\n",drec->Type);
		printf("  Len %u\n",ntohs(drec->Len));
		printf("\n");
				
		numbytes=recv(sockfd, &Buff[sizeof(DRec)], ntohs(drec->Len)-sizeof(DRec),0);
		
		switch (drec->Type){
		case LDATA_TYPE_STATISTICS:
			{
			DRecStat*	drecstat;
			int			Time;
			
			drecstat=(DRecStat*)Buff;
			Time=ntohl(drecstat->Time);
			tm=localtime((void*)&Time);
			printf("Sensor statistics:\n");
			printf("  Time %i/%i/%i %02i:%02i:%02i\n",tm->tm_mon+1, tm->tm_mday, tm->tm_year+1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
			printf("  Total Packets/sec %u\n",ntohs(drecstat->PacketCount));
			printf("  TCP Packets/sec   %u\n",ntohs(drecstat->TCPCount));
			printf("  UDP Packets/sec   %u\n",ntohs(drecstat->UDPCount));
			}
			break;
		case LDATA_TYPE_ALERT:
			{
			DRecAlert*	alert;
			
			printf("Alert:\n");
			printf("  Message %s\n",alert->Message);
			}
			break;
		default:
			printf("Unknown message type\n");
		}

	}

	close(sockfd);

	return 0;	
}
