#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "decode_tcp.h"
#include "decode_http.h"
#include "../packets/packet.h"
#include "../engine/url.h"
#include "../engine/parse_config.h"

extern GlobalVars	Globals;

HTTPIdentifying		httpi;

int primes[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71 };

inline int BinSearch (int *vec, int n, int value) {
	int sta = 0;
	int end = n - 1;
	int half;

	while (sta <= end) {
		half = (sta + end) / 2;

		if (value < vec[half])
			end = half - 1;
		else if (value > vec[half])
			sta = half + 1;
		else
			return TRUE;
	}

	return FALSE;
}

inline void ShellSort(int *vec, int n) {
	int i, j, val;
	int gap = 1;

	do
		gap = 3 * gap + 1;
	while (gap < n);
	
	do {
		gap /= 3;
		
		for (i = gap; i < n ; i++) {
			val = vec[i];
			j = i - gap;

			while (j >= 0 && val < vec[j]) {
				vec[j+gap] = vec[j];
				j -= gap;
			}

			vec [j+gap] = val;
		}
	} while (gap > 1);
}

int Sum (char *str, int strsize) {
	int sum = 0;
	int i;

	DEBUGPATH;

	if (strsize > MAX_PRIMES) {
		printf ("%s is too big!\n Max allowed method size is %d", str, MAX_PRIMES);
		return -1;
	}

#ifdef DEBUG
	printf ("Sum: %s", str);
#endif

	for (i = 0 ; i < strsize ; i++)
		sum += *str++ * primes[i];

#ifdef DEBUG
	printf (" (%d)\n", sum);
#endif

	if (sum)
		return sum;
	else
		return -1;
}

void *DecodeHTTP (int PacketSlot) {
	HTTPData		*http;
	char			*payloadbegin, *pbaux;
	int			payloadsize, psaux;
	int			sum = 0;
	int			i;

	DEBUGPATH;

	pbaux = Globals.Packets[PacketSlot].RawPacket + Globals.Packets[PacketSlot].BeginData;
	psaux = Globals.Packets[PacketSlot].PacketLen - Globals.Packets[PacketSlot].BeginData;

	for (i = 0 ; i < psaux && i < MAX_PRIMES ; i++, pbaux++)
		if (*pbaux >= 'A' && *pbaux <= 'Z')
			sum += *pbaux * primes[i];
	else if (*pbaux == ' ')
		break;
	else
		return NULL;

	psaux -= i;

	if (*pbaux != ' ')
		return NULL;

	if (!BinSearch(httpi.method, httpi.mnum, sum))
		return NULL;

	for (i = 0 ; i < psaux ; i++, pbaux++)
		if (*pbaux == ' ')
			continue;
	else
		break;

	if (i == psaux)
		return NULL;

	psaux -= i;

	payloadbegin = pbaux;
	payloadsize = psaux;

	for (i = 0 ; i < psaux ; i++, pbaux++)
		if (*pbaux >= '!' && *pbaux <= '~')
			continue;
	else if (*pbaux == ' ')
		break;
	else
		return NULL;

	if (i == psaux)
		return NULL;

	for (i = 0 ; i < psaux ; i++, pbaux++)
		if (*pbaux == ' ')
			continue;
	else if (*pbaux >= '!' && *pbaux <= '~')
		break;
	else
		return NULL;

	if (i == psaux)
		return NULL;

	psaux -= i;

	http = (HTTPData *) malloc (sizeof(HTTPData));

	if (!http) {
		fprintf (stderr, "In DecodeURI: No memory available!\n");
		return NULL;
	}

	http->decoded = URLDecode (payloadbegin, payloadsize, &http->decoded_size);

	http->method = sum;

	return http;
}

int ParseMethods (FILE *fp) {
	char	LineBuff[10240];
	char	*Start, *End;

	while (GetLine(fp, LineBuff, 10240)) {
		if (strcasecmp(LineBuff, "</decoder>") == 0) {
			ShellSort (httpi.method, httpi.mnum);
#ifdef DEBUG
			printf ("All done at HTTPDecoder Configuration\n");
#endif
			return TRUE;
		}

		Start = End = LineBuff;

		while (TRUE) {
			if (httpi.mnum == MAX_METHODS) {
				printf ("Methods count reached the limit\n");
				return FALSE;
			}

			while (*End != ',' && *End != '\0' && *End >= 'A' && *End <= 'Z')
				End++;

			if (*End == ',') {
				*End = '\0';
				if ((httpi.method[httpi.mnum++] = Sum (Start, End - Start)) == -1)
					return FALSE;
				Start = ++End;
				continue;
			} else if (*End == '\0') {
				if ((httpi.method[httpi.mnum++] = Sum (Start, End - Start)) == -1)
					return FALSE;
				break;
			} else {
				printf ("Error ocurred while parsing HTTP Decoder configuration\n");
				return FALSE;
			}
		}
	}

	return FALSE;
}

void FreeHTTP (void *data) {
	free (((HTTPData *) data)->decoded);
	free (data);
}

int InitDecoderHTTP(){
	int			DecoderID;

	DEBUGPATH;

	DecoderID = CreateDecoder("HTTP");

	if (DecoderID == DECODER_NONE) {
#ifdef DEBUG
		printf ("In InitDecoderURI: Couldn't Allocate URI Decoder\n");
#endif
		return FALSE;
	}

	Globals.Decoders[DecoderID].DecodeFunc = DecodeHTTP;
	Globals.Decoders[DecoderID].ConfigFunction = ParseMethods;
	Globals.Decoders[DecoderID].Free=FreeHTTP;

	if (!DecoderAddDecoder(GetDecoderByName("TCP"), DecoderID)) {
		fprintf (stderr, "In InitDecoderHTTP: Failed to bind HTTP Decoder to TCP Decoder\n");
		return FALSE;
	}

	httpi.mnum = 0;

	return TRUE;
}
