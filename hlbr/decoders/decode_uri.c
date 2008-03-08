/*
	PEdroArthur_JEdi (pedroarthur . jedi []IamAtaPlaceThatDon'tLikeSpamers[] gmail com)

	I tried to do my best. If you have a performance patch or found any bug please mail-me
	as soon as possible! Me and the HLBR developers community will be very thankful for
	your contribution.

	Start date: 2007-11-09
	End date: Nowadays (today is 2008-02-22)

	URLDecoder for HLBR

	Description:	This decoder aim to decode URL from HTTP packets by following
			[1] specifications. It will not apply to others URI uses cause
			it lookes for HTTP (and|or) WebDAV mathods before decoding the
			packet payload, so, any others payloads will not match with methods
			identifying's regex and will produce a NULL output.

			I talked about regex. Yes, the identifying function uses regex
			as the main method for identifying the payload as a HTTP packet.
			So, I divided the regex in fragments dedicated for only one type
			of methods, leaving to the HLBR administration user to choose which
			packs of methods to check.

			It's just like this:
				1 - HTTP Methods, based on [2]
				2 - WebDAV Methods, based on [3]
				3 - WebDAV Versioning Extension Methods, based on [4]
				4 - Microsoft(r) WebDAV Methods, base on [5]

			It is a good deal to enable WebDAV methods while using MS WebDAV cause
			the last is just a "extension" to the first, as you may see comparing
			the methods specification at [3] and [5].

			For sake of performance, the URIDecoder is configurable by the user.
			You must enable only the methods you run on your network, avoiding
			the delay caused by other methods identifying schemas. So, if you run
			WebDAV without Versioning at a Apache Server by the grace of the mod_webdav,
			DON'T enable MS WebDAV. You will gain some CPU cicles by doing this!
			Globaly, it is inteligent to maintain HLBR as clean as possible.

			[1] Uniform Resource Identifier (URI): General Syntax, RFC 3986 [BERNERS-LEE at al.]
			[2] Hypertext Transfer Protocol -- HTTP/1.1, RFC 2616 [FIELDING at al.]
			[3] HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV), RFC 4918 [DUSSEAULT at al.]
			[4] Versioning Extensions to WebDAV, RFC 3253 [CLEMM at al.]
			[5] Microsoft WebDAV, http://msdn2.microsoft.com/en-us/library/aa142917.aspx in 2008-02-19

*/

#include <stdlib.h>
#include <stdio.h>

#include "decode.h"
#include "decode_tcp.h"
#include "decode_uri.h"
#include "../packets/packet.h"
#include "../engine/regex.h"

#define DEBUG

#define DECODE_WEBDAV_METHODS
#define DECODE_WEBDAV_AUTHVER_METHODS
#define DECODE_MSWEBDAV_METHODS

typedef struct http_identifying_ds {
	HLBRRegex			*regex;
	struct	http_identifying_ds	*next;

#ifdef DEBUG
	char				*method_name;
#endif

} HttpIdentifying;

extern GlobalVars	Globals;

HttpIdentifying		*http_identifying;

inline char min (unsigned char a, unsigned char b, unsigned char c) {
	return a < b ? (a < c ? a : c+10) : (b < c ? b+10 : c+10);
}

inline char urietohex (unsigned char *str) {
	return min (str[0] - '0', str[0] - 'a', str[0] - 'A') * 16 + min (str[1] - '0', str[1] - 'a', str[1] - 'A');
}

inline int isencoded (char *str) {
	if (
		(
			(str[0] > 0x60 && str[0] < 0x67) ||
			(str[0] > 0x40 && str[0] < 0x47) ||
			(str[0] > 0x2F && str[0] < 0x3A)
		)
				&&
		(
			(str[1] > 0x60 && str[1] < 0x67) ||
			(str[1] > 0x40 && str[1] < 0x47) ||
			(str[1] > 0x2F && str[1] < 0x3A)
		)
	)
		return TRUE;

	return FALSE;
}

char *url_decode (char *content, int content_len, int *decoded_size) {
	char	*decoded;
	int	i;

	DEBUGPATH;

	decoded = (char *) calloc (content_len, sizeof(char));

	if (!decoded) {
		printf ("In DecodeURI(url_decoded): No memory available!");
		return NULL;
	}

#ifdef DEBUG
	printf ("URL Encoded: ");
	for (i = 0 ; i < content_len ; i++)
		fputc (content[i], stdout);
	printf ("\n");
#endif

	for (i = 0 , *decoded_size = 0 ; i < content_len ; i++) {
		if (content[i] == '+')
			decoded[(*decoded_size)++] = 0x20;
		else if (content[i] != '%')
			decoded[(*decoded_size)++] = content[i];
		else if (( i+1 < content_len) && ( i+2 < content_len) && isencoded(&content[++i]))
			decoded[(*decoded_size)++] = urietohex (&content[i++]);
		else {
			decoded[(*decoded_size)++] = '%';
			if (content[i] == '%') i++;
		}
	}

#ifdef DEBUG
	printf ("URL Decoded: ");
	for (i = 0 ; i < *decoded_size ; i++)
		fputc (decoded[i], stdout);
	printf ("\n");
#endif

	return decoded;
}

void *DecodeURI (int PacketSlot) {
	char			*payloadbegin;
	int			payloadsize;

	HttpIdentifying		*aux;

	DEBUGPATH;

	payloadbegin = Globals.Packets[PacketSlot].RawPacket + Globals.Packets[PacketSlot].BeginData;
	payloadsize = Globals.Packets[PacketSlot].PacketLen - Globals.Packets[PacketSlot].BeginData;

	for (aux = http_identifying ; aux ; aux = aux->next) {
		if (RegexExec(aux->regex, payloadbegin, payloadsize)) {
			URIData			*uri;
#ifdef DEBUG
			printf ("In DecodeURI: Packet match %s\n", aux->method_name);
#endif
			uri = (URIData *) malloc (sizeof(URIData));

			if (!uri) {
				printf ("In DecodeURI: No memory available!\n");
				return NULL;
			}

			uri->decoded = url_decode (payloadbegin, payloadsize, &uri->decoded_size);

			return uri;
		}
#ifdef DEBUG
		else
			printf ("In DecodeURI: Packet don't match %s\n", aux->method_name);
#endif
	}
	return NULL;
}

int InitDecoderURI(){
	int			DecoderID;
	HttpIdentifying		*aux;

	DEBUGPATH;

	DecoderID = CreateDecoder("URI");

	if (DecoderID == DECODER_NONE) {
#ifdef DEBUG
		printf ("In InitDecoderURI: Couldn't Allocate URI Decoder\n");
#endif
		return FALSE;
	}

	Globals.Decoders[DecoderID].DecodeFunc = DecodeURI;

	if (!DecoderAddDecoder(GetDecoderByName("TCP"), DecoderID)) {
		printf ("In InitDecoderURI: Failed to bind URI Decoder to TCP Decoder\n");
		return FALSE;
	}

	http_identifying = NULL;
	http_identifying = (HttpIdentifying *) calloc (1, sizeof(HttpIdentifying));

	if (!http_identifying) {
		printf ("In InitDecoderURI: No memory available");
		return FALSE;
	}

	http_identifying->regex = RegexCompile(HTTP_METHODS_REGEX, 0, NOTEMPTY, 0);

#ifdef DEBUG
	http_identifying->method_name = "HTTP Methods";
	printf ("In InitDecoderURI: added HTTP Methods\n");
#endif

#ifdef DECODE_WEBDAV_METHODS
	aux = http_identifying;

	while (aux->next)
		aux = aux->next;

	aux->next = (HttpIdentifying *) calloc (1, sizeof(HttpIdentifying));

	if (!aux->next) {
		printf ("In InitDecoderURI: No memory available");
		return FALSE;
	}

	aux = aux->next;

	aux->regex = RegexCompile(WEBDAV_METHODS_REGEX, 0, NOTEMPTY, 0);

#ifdef DEBUG
	aux->method_name = "WebDAV Methods";
	printf ("In InitDecoderURI: added %s\n", aux->method_name);
#endif
#endif
	
	
#ifdef DECODE_WEBDAV_AUTHVER_METHODS
	aux = http_identifying;

	while (aux->next)
		aux = aux->next;

	aux->next = (HttpIdentifying *) calloc (1, sizeof(HttpIdentifying));

	if (!aux->next) {
		printf ("In InitDecoderURI: No memory available");
		return FALSE;
	}

	aux = aux->next;

	aux->regex = RegexCompile(WEBDAV_EX_METHODS_REGEX, 0, NOTEMPTY, 0);

#ifdef DEBUG
	aux->method_name = "WebDAV Authoring and Versioning Methods";
	printf ("In InitDecoderURI: added %s\n", aux->method_name);
#endif
#endif

#ifdef DECODE_MSWEBDAV_METHODS
	aux = http_identifying;
	
	while (aux->next)
		aux = aux->next;

	aux->next = (HttpIdentifying *) calloc (1, sizeof(HttpIdentifying));

	if (!aux->next) {
		printf ("In InitDecoderURI: No memory available");
		return FALSE;
	}

	aux = aux->next;

	aux->regex = RegexCompile(MS_WEBDAV_METHODS_REGEX, 0, NOTEMPTY, 0);

#ifdef DEBUG
	aux->method_name = "Microsoft(r) WebDAV Methods";
	printf ("In InitDecoderURI: added %s\n", aux->method_name);
#endif
#endif

	for (aux = http_identifying ; aux ; ) {
#ifdef DEBUG
		printf ("In InitDecoderURI: checking %s\n", aux->method_name);
#endif
		if (!aux->regex) {
			HttpIdentifying *aux2;

			printf ("Error ocurr while seting up URI Decoder\n");
#ifdef DEBUG
			printf ("In InitDecoderURI: %s regex compilation failed\n", aux->method_name);
#endif
			aux2 = aux->next;
			free (aux);
			aux = aux2;

		} else
			aux = aux->next;
	}

	if (!http_identifying)
		return FALSE;

	return TRUE;
}

#ifdef DEBUG
#undef DEBUG
#endif
