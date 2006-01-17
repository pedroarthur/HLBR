#ifndef _HOGWASH_ACTION_ALERT_SYSLOG_H_
#define _HOGWASH_ACTION_ALERT_SYSLOG_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "../engine/message.h"
#include "action.h"
#include <sys/syslog.h>

extern GlobalVars Globals;

int InitActionAlertSyslog();

#endif	/* _HOGWASH_ACTION_ALERT_SYSLOG_H_ */
