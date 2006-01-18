#ifndef _HLBR_ACTION_ALERT_SYSLOG_H_
#define _HLBR_ACTION_ALERT_SYSLOG_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "../engine/message.h"
#include "action.h"
#include <sys/syslog.h>

extern GlobalVars Globals;

int InitActionAlertSyslog();

#endif	/* _HLBR_ACTION_ALERT_SYSLOG_H_ */
