#include <pcre.h>

#define DEBUG

#define HTTP_METHODS		0x0001
#define WEBDAV_METHODS		0x0010
#define WEBDAV_EX_METHODS	0x0100
#define MS_WEBDAV_METHODS	0x1000

#define HTTP_CONTENT_REGEX "[[:print:]]*?HTTP/1\\.[01]"

#define HTTP_METHODS_REGEX "(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"HTTP_CONTENT_REGEX

#define WEBDAV_METHODS_REGEX "(COPY|MOVE|PROP(FIND|PATCH)|(UN)?LOCK|MKCOL|NOTIFY|POLL)"HTTP_CONTENT_REGEX
#define WEBDAV_EX_METHODS_REGEX "(VERSION-CONTROL|REPORT|CHECKIN|(UN)?CHECKOUT|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY)"HTTP_CONTENT_REGEX

#define MS_WEBDAV_METHODS_REGEX "(B(COPY|MOVE|DELETE|PROP(FIND|PATCH))|X-MS-ENUMATTS|(UN)?SUBSCRIBE)"HTTP_CONTENT_REGEX

typedef struct uridata {
	char	*decoded;
	int	decoded_size;
} URIData;

typedef struct http_identifying_ds {
	pcre				*re;
	pcre_extra			*ere;
	struct	http_identifying_ds	*next;
#ifdef DEBUG
	char				*method_name;
#endif
} HttpIdentifying;

char *url_decode (char *content, int content_len, int *decoded_size);
void *DecodeURI (int PacketSlot);
int InitDecodeURI();

#ifdef DEBUG
#undef DEBUG
#endif
