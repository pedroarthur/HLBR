#ifndef _HLBR_ACTION_ALERT_LISTENSOCKET_H_
#define _HLBR_ACTION_ALERT_LISTENSOCKET_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "action.h"

#define PREMAGIC	0x11223344

#define LDATA_TYPE_STATISTICS	1
#define LDATA_TYPE_ALERT		2

typedef struct listen_data_record{
	unsigned int	PreMagic;
	unsigned char	Type;
	unsigned short	Len;
} DRec;

typedef struct listen_data_record_stats{
	unsigned int	PreMagic;
	unsigned char	Type;
	unsigned short	Len;
	
	int				Time;
	unsigned short	PacketCount;
	unsigned short	TCPCount;
	unsigned short	UDPCount;
} DRecStat;

typedef struct listen_data_record_alert{
	unsigned int	PreMagic;
	unsigned char	Type;
	unsigned short	Len;

	unsigned char	Message[1024];	
} DRecAlert;


int InitActionAlertListenSocket();

#endif
