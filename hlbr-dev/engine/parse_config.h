#ifndef _HOGWASH_PARSE_CONFIG_H_
#define _HOGWASH_PARSE_CONFIG_H_

#include "../config.h"
#include "hogwash.h"
#include <stdio.h>

int ParseConfig();
int GetLine(FILE* fp, char* buff, int buff_len);

#endif
