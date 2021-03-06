#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "action_alert_syslog.h"

#if 0
#define DEBUG
#define DEBUGPATH 1
#endif

#include "../engine/hlbrlib.h"

typedef struct _hlbr_syslog_t {
    char *name;
    int val;
} hlbr_syslog_t;

hlbr_syslog_t hlbr_syslog_prioritys[] = {
    {"LOG_ALERT", LOG_ALERT},
    {"LOG_CRIT", LOG_CRIT},
    {"LOG_DEBUG", LOG_DEBUG},
    {"LOG_EMERG", LOG_EMERG},
    {"LOG_ERR", LOG_ERR},
    {"LOG_INFO", LOG_INFO},
    {"LOG_NOTICE", LOG_NOTICE},
    {"LOG_WARNING", LOG_WARNING},
};

hlbr_syslog_t hlbr_syslog_facilitys[] = {
#ifdef LOG_AUTHPRIV	
    {"LOG_AUTHPRIV", LOG_AUTHPRIV},
#endif	
#ifdef LOG_FTP
    {"LOG_FTP", LOG_FTP},
#endif
    {"LOG_AUTH", LOG_AUTH},
    {"LOG_CRON", LOG_CRON},
    {"LOG_DAEMON", LOG_DAEMON},
    {"LOG_KERN", LOG_KERN},
    {"LOG_LPR", LOG_LPR},
    {"LOG_MAIL", LOG_MAIL},
    {"LOG_NEWS", LOG_NEWS},
    {"LOG_SYSLOG", LOG_SYSLOG},
    {"LOG_USER", LOG_USER},
    {"LOG_UUCP", LOG_UUCP},
    {"LOG_LOCAL0", LOG_LOCAL0},
    {"LOG_LOCAL1", LOG_LOCAL1},
    {"LOG_LOCAL2", LOG_LOCAL2},
    {"LOG_LOCAL3", LOG_LOCAL3},
    {"LOG_LOCAL4", LOG_LOCAL4},
    {"LOG_LOCAL5", LOG_LOCAL5},
    {"LOG_LOCAL6", LOG_LOCAL6},
    {"LOG_LOCAL7", LOG_LOCAL7},
};

hlbr_syslog_t hlbr_syslog_options[] = {

#ifdef LOG_CONS
    {"LOG_CONS", LOG_CONS},	/* Write directly to system console if  there  is  an  error  while sending to system logger. */
#endif
#ifdef LOG_NDELAY
    {"LOG_NDELAY", LOG_NDELAY},	/* Open  the  connection  immediately */
#endif
#ifdef LOG_NOWAIT
    {"LOG_NOWAIT", LOG_NOWAIT},	/* Don't wait for child processes that may have been created  while logging the message. */
#endif
#ifdef LOG_ODELAY
    {"LOG_ODELAY", LOG_ODELAY},	/* The converse of LOG_NDELAY; opening of the connection is delayed */
#endif
#ifdef LOG_PERROR
    {"LOG_PERROR", LOG_PERROR},	/* (Not in SUSv3.) Print to stderr as well. */
#endif
#ifdef LOG_PID
    {"LOG_PID", LOG_PID},	/* Include PID with each message */
#endif
};


typedef struct action_syslog_rec_t {
    int priority, facility, options;
    int Active;
} ActionSyslogRec;

/* Shutdown syslog handler call closelog() */
int ActionAlertSyslogShutdownFunc(void *Data)
{
    ActionSyslogRec *data;

    DEBUGPATH;

    if (!Data) {
	DBG((printf("FAILED: %s(%p)\n", __FUNCTION__, Data)));
	return FALSE;
    }

    data = (ActionSyslogRec *) Data;
    if (data->Active == TRUE)
	closelog();
    memset(&data, 0x0, sizeof(ActionSyslogRec *));
    return TRUE;
}

/* call openlog() and setup shutdown handler for syslog */
int SyslogInit(ActionSyslogRec * Data)
{
    ActionSyslogRec *data;

    DEBUGPATH;

    if (!Data) {
	DBG((printf("FAILED: %s(%p)\n", __FUNCTION__, Data)));
	return FALSE;
    }
    data = (ActionSyslogRec *) Data;
    openlog("hlbr", data->options, data->facility);
    DBG((printf
	 ("Calling openlog(\"%s\", 0%x, 0%x)\n", "hlbr", data->options,
	  data->facility)
	));
    data->Active = TRUE;
    AddShutdownHandler(ActionAlertSyslogShutdownFunc, data);
    return TRUE;
}


/* handle info messages */
int AlertSyslogMessage(char *Message, void *Data)
{
    ActionSyslogRec *data;

    DEBUGPATH;

    if (!Data) {
	DBG((printf("FAILED: %s(%p)\n", __FUNCTION__, Data)));
	return FALSE;
    }
    data = (ActionSyslogRec *) Data;
    if (data->Active != TRUE)
	SyslogInit(data);

    syslog(data->priority, "%s", ((Message != NULL) ? Message : "ALERT!"));
    return TRUE;
}

/* Write the alert message to syslog */
int AlertSyslogAction(int RuleNum, int PacketSlot, void *Data)
{
    char Buff[1024];
    PacketRec *p;
    ActionSyslogRec *data;

    DEBUGPATH;
    DBG((printf("Sending alert to syslog\n")));

    if (!Data) {
	DBG((printf("FAILED: %s(%p)\n", __FUNCTION__, Data)));
	return FALSE;
    }

    data = (ActionSyslogRec *) Data;

    if (data->Active != TRUE)
	SyslogInit(data);

    p = &Globals.Packets[PacketSlot];
    if (!ApplyMessage
	(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)) {
	printf("Couldn't apply message to packet for syslog\n");
	return FALSE;
    }

    syslog(data->priority, "%s", ((Buff != NULL) ? Buff : "ALERT!"));
    return TRUE;
}

void *AlertSyslogParseArgs(char *Args)
{
    int idx;
    char *ptr;
    ActionSyslogRec *data;
    QueueList *ll, *list;
    QueueList *opt, *options;

    opt = options = ll = list = NULL;
    ptr = NULL;

    DEBUGPATH;
    DBG((printf("%s(%s)\n", __FUNCTION__, Args)));

    data = (ActionSyslogRec *) calloc(sizeof(ActionSyslogRec), 1);
    data->options = 0;
    data->facility = LOG_AUTH;
    data->priority = LOG_INFO;

    list = ListAdd(Args, list, ',');
    for (ll = list; ll != NULL; ll = ll->next) {
	if ((ptr = ParseCmp("facility", ll->item)) != NULL) {
	    for (idx = 0; idx < ARRAYSIZE(hlbr_syslog_facilitys); idx++) {
		if (strcasecmp(hlbr_syslog_facilitys[idx].name, ptr) == 0) {
		    DBG((printf
			 ("facility(%s) = %d\n", ptr,
			  hlbr_syslog_facilitys[idx].val)));
		    data->facility = hlbr_syslog_facilitys[idx].val;
		}
	    }
	    FREE(ptr);
	}
	if ((ptr = ParseCmp("priority", ll->item)) != NULL) {
	    for (idx = 0; idx < ARRAYSIZE(hlbr_syslog_prioritys); idx++) {
		if (strcasecmp(hlbr_syslog_prioritys[idx].name, ptr) == 0) {
		    DBG((printf
			 ("priority(%s) = %d\n", ptr,
			  hlbr_syslog_prioritys[idx].val)));
		    data->priority = hlbr_syslog_prioritys[idx].val;
		}
	    }
	    FREE(ptr);
	}
	if ((ptr = ParseCmp("options", ll->item)) != NULL) {
	    options = ListAdd(ptr, options, '|');
	    for (opt = options; opt != NULL; opt = opt->next) {
		for (idx = 0; idx < ARRAYSIZE(hlbr_syslog_options); idx++) {
		    if (strcasecmp(hlbr_syslog_options[idx].name, opt->item)
			== 0) {
			DBG((printf
			     ("priority(%s) = %d\n", opt->item,
			      hlbr_syslog_options[idx].val)));
			data->options |= hlbr_syslog_options[idx].val;
		    }
		}
	    }
	    ListClear(options);
	    FREE(ptr);
	}
    }
    ListClear(list);
    return data;
}


/********************************
* Set up the alert Syslog stuff
********************************/
int InitActionAlertSyslog()
{
    int ActionID;

    DEBUGPATH;

    ActionID = CreateAction("alert syslog");
    if (ActionID == ACTION_NONE) {
	DBG((printf("Couldn't allocation action alert syslog\n")));
	return FALSE;
    }

    Globals.ActionItems[ActionID].ActionFunc = AlertSyslogAction;
    Globals.ActionItems[ActionID].MessageFunc = AlertSyslogMessage;
    Globals.ActionItems[ActionID].ParseArgs = AlertSyslogParseArgs;

    return TRUE;
}
