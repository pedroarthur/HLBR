#ifndef _HLBR_PARSE_RULES_H_
#define _HLBR_PARSE_RULES_H_

#include "../config.h"
#include "hlbr.h"
#include <stdio.h>

/* In case were getting told our table name from config.h */
//#ifndef RULES_MYSQL_TABLENAME
//#define RULES_MYSQL_TABLENAME "Rules"
//#endif

int ParseRules(char* FName);
int ParseDecoderLine(char* DecoderLine, int RuleNum);
int SetAction(int RuleID, char* ActionName);

#endif
