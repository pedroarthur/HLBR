#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>

#include "hlbr.h"
#include "regex.h"
#include "alert_limit.h"

extern GlobalVars	Globals;

AlertLimit *ParseRuleAlertLimit (char *Args) {
	AlertLimit	*Limit;
	HLBRRegex	*opt_identifying_regex;
	char 		div;
	int 		i;

	DEBUGPATH;

	opt_identifying_regex = CompileRegex (ARGS_PARSE_REGEX, ANCHORED, 0, 0);

	if (!opt_identifying_regex) {
		printf ("Can't allocate memory for Alert Limit parser\n");
		return NULL;
	}

	if (!RegexExec(opt_identifying_regex, Args, strlen(Args))) {
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

	DEBUGPATH;

	if (Globals.Rules[RuleNum].Limit) {
		time_t	time_now = time(NULL);

		if (Globals.Rules[RuleNum].Limit->next_match > time_now) {
#ifdef DEBUG
			printf ("Limit for rule %d reached\n", RuleNum);
#endif
			return FALSE;
		}

		if (++Globals.Rules[RuleNum].Limit->match_count >= Globals.Rules[RuleNum].Limit->match_limit) {
#ifdef DEBUG
			printf ("Limit for rule %d reached\n");
			printf ("Next match in %d seconds\n", Globals.Rules[RuleNum].Lmit->interval);
#endif
			Globals.Rules[RuleNum].Limit->next_match = time_now + Globals.Rules[RuleNum].Limit->interval;
			Globals.Rules[RuleNum].Limit->match_count = 0;
			return TRUE;
		}
	}

	return TRUE;
}
