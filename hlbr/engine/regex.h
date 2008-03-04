#ifndef HLBR_REGEX_H
#define HLBR_REGEX_H

#include <pcre.h>

/* Compilation time options */
#define ANCHORED	PCRE_ANCHORED
#define DOT_MATCH_ALL	PCRE_DOTALL
#define CASELESS	PCRE_CASELESS
#define MULTILINE	PCRE_MULTILINE
#define UNGREEDY	PCRE_UNGREEDY

/* Execution time options */
#define NOTEMPTY	PCRE_NOTEMPTY

#define SVECTOR_SIZE	3

typedef struct hlbr_regex {
	pcre		*re;
	pcre_extra	*ere;
	int		options;
	int		offset;
} HLBRRegex;

HLBRRegex *RegexCompile (char *Args, int coptions, int eoptions, int offset);
int RegexExec (HLBRRegex *regex, char *data, int data_size);
int RegexExecDebug (HLBRRegex *regex, char *data, int data_size);

#endif
