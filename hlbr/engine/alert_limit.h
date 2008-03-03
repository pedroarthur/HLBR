#ifndef HLBR_LIMIT_PARSER
#define HLBR_LIMIT_PARSER

#define ARGS_PARSE_REGEX "[[:digit:]]+//[smhdw]"

#define SECOND	1
#define MINUTE 	60 * SECOND
#define HOUR	60 * MINUTE
#define DAY	24 * HOUR
#define WEEK	7 * DAY

AlertLimit	*ParseRuleAlertLimit (char *Args);
int		CheckLimit (int RuleNum);

#endif
