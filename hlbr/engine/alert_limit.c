#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>

#include "hlbr.h"
#include "alert_limit.h"

extern GlobalVars	Globals;

pcre			*opt_identifying_regex;

AlertLimit *ParseRuleAlertLimit (char *Args) {
	AlertLimit	*Limit;
	char 		div;
	int 		i;

	if (!opt_identifying_regex)
		opt_identifying_regex = pcre_compile(ARGS_PARSE_REGEX, 0, NULL, NULL, NULL);

	if (pcre_exec(opt_identifying_regex, NULL, Args, strlen(Args), 0, 0, NULL, 0) < 0) {
		printf ("Bad alert limit: %s\n", Args);
		return NULL;
	}

	Limit = (AlertLimit *) calloc (1 , sizeof(AlertLimit));

	if (!Limit) {
		printf ("Couldn't allocate memomry for alert limit\n");
		return NULL;
	}

	Limit->match_limit = strtol (Args, NULL, 10);
	Limit->next_match = (time_t) 0;
	Limit->match_count = 0;

	for (i = 0 ; Args[i] != '/' ; i++);

	div = Args[++i];

	switch (div) {
		case 's':
		case 'S':
			Limit->interval = SECOND;
			break;
		case 'm':
		case 'M':
			Limit->interval = MINUTE;
			break;
		case 'h':
		case 'H':
			Limit->interval = HOUR;
			break;
		case 'd':
		case 'D':
			Limit->interval = DAY;
			break;
		case 'w':
		case 'W':
			Limit->interval = WEEK;
			break;
	}

	return Limit;
}

int CheckLimit (int RuleNum) {
	if (Globals.Rules[RuleNum].Limit) {
		time_t	time_now = time(NULL);

		if (Globals.Rules[RuleNum].Limit->next_match > time_now)
			return FALSE;

		if (++Globals.Rules[RuleNum].Limit->match_count >= Globals.Rules[RuleNum].Limit->match_limit) {
			Globals.Rules[RuleNum].Limit->next_match = time_now + Globals.Rules[RuleNum].Limit->interval;
			Globals.Rules[RuleNum].Limit->match_count = 0;
			return TRUE;
		}
	}

	return TRUE;
}
