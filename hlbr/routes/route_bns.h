#ifndef HLBR_BNS_H
#define HLBR_BNS_H

#include "../config.h"
#include "../engine/hlbr.h"
#include "route.h"

#define MAX_BNS		1024

/***********************************
* An IP can be on more than 1 interface
***********************************/
typedef struct bns_mac_interface{
	unsigned char	Mac[6];
	unsigned char	Interface;
} BNS_MAC;

typedef struct bns_mac_ip{
	unsigned int	IP;
	unsigned char	HasProd;
	unsigned char	ProdMac[6];
	unsigned char	HasHoney;
	unsigned char	HoneyMac[6];
} BNS_IP;

/*List if IPs that are begin rerouted to the honeypot*/
NumList*	BNSRerouteList;

int InitRouteBNS();


#endif

