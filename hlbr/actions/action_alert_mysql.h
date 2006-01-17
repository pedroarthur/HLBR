#ifndef _HOGWASH_ACTION_ALERT_MYSQL_H_
#define _HOGWASH_ACTION_ALERT_MYSQL_H_

#include "../config.h"
#include "../engine/hogwash.h"
#include "../engine/message.h"
#include "action.h"


extern GlobalVars Globals;

/* In case were getting told our table name from config.h */
#ifndef ACTION_ALERT_MYSQL_TABLENAME_ALERT
#define ACTION_ALERT_MYSQL_TABLENAME_ALERT "Alerts"
#endif

#ifndef ACTION_ALERT_MYSQL_TABLENAME_MESSAGE
#define ACTION_ALERT_MYSQL_TABLENAME_MESSAGE "Messages"
#endif

#if !(!defined(HAS_MYSQL))
extern int ActionAlertMysqlShutdownFunc();
#endif

extern int InitActionAlertMysql();

#endif /* _HOGWASH_ACTION_ALERT_MYSQL_H_ */
