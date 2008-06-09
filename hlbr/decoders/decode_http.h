#ifndef _HLBR_DECODE_HTTP_H
#define _HLBR_DECODE_HTTP_H

#define MAX_METHODS 64
#define MAX_PRIMES 20

typedef struct httpdata {
	char	*decoded;
	int	decoded_size;
	int	method;
} HTTPData;

typedef struct http_identifying_ds {
	int method[MAX_METHODS];
	int mnum;
} HTTPIdentifying;

int InitDecoderHTTP();

/* Auxiliar functions, used externaly */
inline int BinSearch (int *vec, int n, int value);
inline void ShellSort(int vet[], int lim_sup);

#endif
