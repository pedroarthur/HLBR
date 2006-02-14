/*
 * File: regex.c
 *
 * Description: library to use regular expressions
 *
 * History: 
 *          date - sf login - description
 *
 *          01/18/2006 - morphbr;vivijim - coded this file
 *
 */
#include "regex.h"

//int match(char *string, char *pattern, regex_t *re)
int match(char *string, regex_t *re)
{
	int     status;
        status = regexec( re, string, 0, NULL, 0);
        return(status);

	//It will compile the pattern (regcomp)
	//and execute it on the string (regexec)
	//if found return status (0)
//        if((status=regcomp( re, pattern, REG_EXTENDED))!= 0)
//                return(status);
//        status = regexec( re, string, 0, NULL, 0);
//        return(status);
}
