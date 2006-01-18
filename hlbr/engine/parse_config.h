#ifndef _HLBR_PARSE_CONFIG_H_
#define _HLBR_PARSE_CONFIG_H_

#include "../config.h"
#include "hlbr.h"
#include <stdio.h>

int ParseConfig();
int GetLine(FILE* fp, char* buff, int buff_len);

#endif
