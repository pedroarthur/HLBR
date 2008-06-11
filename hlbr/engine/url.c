#include <stdlib.h>
#include <stdio.h>

#include "hlbr.h"
#include "url.h"

inline char min (unsigned char a, unsigned char b, unsigned char c) {
	return a < b ? (a < c ? a : c + 10) : (b < c ? b + 10 : c + 10);
}

inline char urietohex (unsigned char *str) {
	return min (str[0] - '0', str[0] - 'a', str[0] - 'A') * 16 + min (str[1] - '0', str[1] - 'a', str[1] - 'A');
}

inline int isencoded (char *str) {
	return
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
			);
}


char *URLDecode (char *content, int content_len, int *decoded_size) {
	char	*decoded;
	int	i;

	DEBUGPATH;

	decoded = (char *) malloc (content_len * sizeof(char));

	if (!decoded) {
		fprintf (stderr, "In DecodeURI(url_decoded): No memory available!");
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
