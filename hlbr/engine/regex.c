#include <stdio.h>
#include <pcre.h>

#include "hlbr.h"
#include "regex.h"

HLBRRegex *RegexCompile (char *Args, int coptions, int eoptions, int offset) {
	HLBRRegex 		*regex;
	const char		*erromsg;
	int			erroffset;

	DEBUGPATH;

	if (!Args) {
		printf ("In RegexCompile: NULL argument\n");
		return NULL;
	}

	regex = (HLBRRegex *) calloc (1, sizeof(HLBRRegex));

	regex->re = pcre_compile (Args, coptions, &erromsg, &erroffset, NULL);

	if (regex->re) {
		regex->offset = offset;
		regex->options = eoptions;
		regex->ere = pcre_study (regex->re, 0, &erromsg);
		return regex;
	}

	fprintf(stderr, "Regex Compile error\n Regex: %s\nError Message: %s\nError Offset: %d", Args, erromsg, erroffset);

	free (regex);

	return NULL;
}

int RegexExec (HLBRRegex *regex, char *data, int data_size) {
	DEBUGPATH;

	if (pcre_exec(regex->re, regex->ere, data, data_size, regex->offset, regex->options, NULL, 0) >= 0)
		return TRUE;
	else
		return FALSE;
}


int RegexExecDebug (HLBRRegex *regex, char *data, int data_size) 
{
	int 	rvalue;
	int	svector[SVECTOR_SIZE];
	int 	i,j;

	DEBUGPATH;

	rvalue = pcre_exec(regex->re, regex->ere, data, data_size, regex->offset, regex->options, svector, SVECTOR_SIZE);

	for (i = 0 ; rvalue >= 0 ; i++) {
		printf ("Match[%d]: StartOffset %d EndOffset %d\n", i, svector[0], svector[1]);
		printf ("Matched String: ");
		for (j = 0 ; j < svector[1] - svector[0] ; j++)
			putchar (data[svector[0]+j]);
		putchar ('\n');
		rvalue = pcre_exec(regex->re, regex->ere, data, data_size, svector[1], regex->options, svector, SVECTOR_SIZE);
		printf(data);
	}

	if (i)
		return TRUE;
	else
		return FALSE;
}
