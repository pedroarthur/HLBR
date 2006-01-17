#ifndef _HOGWASH_DECODE_DNS_H_
#define _HOGWASH_DECODE_DNS_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "decode.h"

#define MAX_DNS_QUESTIONS	5
#define MAX_DNS_QUERY_LEN	1024

/***********************************************
* I'm making these up as I go so these will
* probably have to be rewritten
***********************************************/

typedef struct dns_header_1 {
	unsigned short	TransactionID;
	unsigned short	Flags;
	unsigned short	Questions;
	unsigned short	AnswerRR;
	unsigned short	AuthorityRR;
	unsigned short	AdditoinalRR;
} DNSHeader1;

typedef struct dns_qestion{
	unsigned char			Query[MAX_DNS_QUERY_LEN];
	unsigned short*			Type;
	unsigned short*			Class;
} DNSQuestion;

#define DNS_FLAG_QUERY		0x80

typedef struct dns_data{
	DNSHeader1*		Header1;
	DNSQuestion		Q[MAX_DNS_QUESTIONS];
} DNSData;


int InitDecoderDNS();

#endif
