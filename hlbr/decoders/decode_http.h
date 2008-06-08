#ifndef _HLBR_DECODE_HTTP_H
#define _HLBR_DECODE_HTTP_H

#define MAX_METHODS 64
#define MAX_PRIMES 20

typedef struct httpdata {
	char	*decoded;
	int	decoded_size;
	int	method;
} HTTPData;

int InitDecoderHTTP();
int Sum (char *str, int strsize);

#endif
