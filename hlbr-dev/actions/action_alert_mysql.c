/*
 *
 * Author: solar@linbsd.net
 * File: action_alert_mysql.c
 * License: GNU General Public License (GPL)
 * Indent Options: 
 *	indent -kr -nbad -i4 -br -ce -nbc -npcs -cli4 -sc action_alert_mysql.c
 *
 * This file was made possible thanks to 
 * (K.A.S Offering Secure Managed Security Solutions) http://www.kas.net.au
 */

/*
 *  
 * Hogwash  (Inline packet scrubber)
 * Copyright (C) 2001,2002,2003  Jason Larsen
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../config.h"

#ifndef HAS_MYSQL
#include <stdio.h>
/* dummy call for those builds that don't have MYSQL support */
int InitActionAlertMysql()
{

#ifdef DEBUG
    printf("There is no MYSQL support\n");
#endif
	
    return TRUE;
}
#else

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <mysql/mysql.h>

#if 0
#define DEBUG
#define DEBUGPATH 1
#endif

#include "action_alert_mysql.h"
#include "../engine/hoglib.h"

typedef struct action_mysql_rec_t {
    char *DBase;
    char *DBUser;
    char *DBPass;
    char *DBHost;
    unsigned int DBPort;
    int Active;
    int LogPackets;
    MYSQL sql;
} ActionMysqlRec;


/* Create MySQL Connection */
int MysqlDbaseInit(ActionMysqlRec * data)
{
    MYSQL sql;

    DEBUGPATH;

    mysql_init(&data->sql);
/*
    Note that upon connection, mysql_real_connect() sets the reconnect flag 
    (part of the MYSQL structure) to a value of 1. This flag indicates, in the 
    event that a query cannot be performed because of a lost connection, to try 
    reconnecting to the server before giving up. 
*/
    if (mysql_real_connect(&data->sql,
			   data->DBHost,
			   data->DBUser,
			   data->DBPass, data->DBase, data->DBPort, NULL, 0)
	) {
	printf("Connected: %s@%s:%d using dbase '%s'\n",
	       data->DBUser,
	       data->DBHost, data->DBPort,
	       ((data->DBase != NULL) ? data->DBase : "(none)")
	    );
	data->Active = 1;
	AddShutdownHandler(ActionAlertMysqlShutdownFunc, data);
	return TRUE;
    }

    /* Is stderr closed out? when -d is not invoked? */
    fprintf(stderr, "FAILED: %s\n", mysql_error(&sql));
    return FALSE;
}


/******************************************
* Parse the args for this action
******************************************/
void *AlertMysqlParseArgs(char *Args)
{
    ActionMysqlRec *data;
    QueueList *ll, *list;
    char *ptr;

    DEBUGPATH;

    list = ll = NULL;

    DBG((printf("%s(%s)\n", __FUNCTION__, Args)));

    data = (ActionMysqlRec *) calloc(sizeof(ActionMysqlRec), 1);
    DBG((printf
	 ("%s calloc(%d, 1) = %p\n", __FUNCTION__, sizeof(ActionMysqlRec),
	  data)));

    list = ListAdd(Args, list, ',');
    for (ll = list; ll != NULL; ll = ll->next) {
	DBG((printf("%s(%s)\n", __FUNCTION__, ll->item)));
	if ((ptr = ParseCmp("user", ll->item)) != NULL)
	    data->DBUser = ptr;
	if ((ptr = ParseCmp("host", ll->item)) != NULL)
	    data->DBHost = ptr;
	if ((ptr = ParseCmp("pass", ll->item)) != NULL)
	    data->DBPass = ptr;
	if ((ptr = ParseCmp("dbase", ll->item)) != NULL)
	    data->DBase = ptr;
	if ((ptr = ParseCmp("port", ll->item)) != NULL) {
	    data->DBPort = atoi(ptr);
	    FREE(ptr);
	}
	/* Chances are this option will turn into options=BITWISE|OR|SOME|OPTIONS */
	if ((ptr = ParseCmp("logpackets", ll->item)) != NULL) {
	    data->LogPackets = atoi(ptr);
	    FREE(ptr);
	}
    }
    ListClear(list);

    /* Warn of missing config options */
    if (!data->DBase)
	printf("Warning: No Database\n");
    if (!data->DBUser)
	printf("Warning: No DBUser\n");
    if (!data->DBPass)
	printf("Warning: No DBPass\n");
    if (!data->DBHost)
	printf("Warning: No DBUser\n");

    return data;
}

/* 
 *  Messages are sent when there's a condition with no 
 *  packets, such as a port scan, state table full, etc 
 */
int AlertMysqlMessage(char *Message, void *Data)
{
    char *blob;
    char Buff[1024];
    int len;
    ActionMysqlRec *data;

    DEBUGPATH;

    DBG((printf("Sending a msg to the database.\n")));

    if (!Data || !Message) {
	DBG((printf("No message data to send.\n")));
	return FALSE;
    }

    data = (ActionMysqlRec *) Data;

    if (!data->Active)
	MysqlDbaseInit(data);

    len = strlen(Message);
    blob = (char *) MALLOC((len * 2) + 1);

    if (blob == NULL) {
	DBG((printf("FAILED: malloc %d bytes of memory\n", (len * 2) + 1)));
	return FALSE;
    }
    mysql_real_escape_string(&data->sql, blob, Message, len);

    snprintf(Buff, sizeof(Buff),
	     "INSERT INTO %s(UnixTime, Data) VALUES(%lu,'%s');\n",
	     ACTION_ALERT_MYSQL_TABLENAME_MESSAGE, time(NULL), blob);

    if (mysql_real_query(&data->sql, Buff, strlen(Buff))) {
	fprintf(stderr, "Failed Query('%s') = %s\n", Buff,
		mysql_error(&data->sql));
    }
    FREE(blob);

    return TRUE;
}

/* Write the alert message to the alert database */
int AlertMysqlAction(int RuleNum, int PacketSlot, void *Data)
{
    int sa, sb, sc, sd, src_port;
    int da, db, dc, dd, dst_port;
    int mixed = 0;
    char Buff[1024 + TYPICAL_PACKET_SIZE];
    char *blob;
    ActionMysqlRec *data;
    PacketRec *p;

    DEBUGPATH;

    DBG((printf("Writing to the Alert Database\n")));

    if (!Data) {
	DBG((printf("FAILED: %s(%p)\n", __FUNCTION__, Data)));
	return FALSE;
    }

    p = &Globals.Packets[PacketSlot];
    data = (ActionMysqlRec *) Data;

    if (!ApplyMessage
	(Globals.Rules[RuleNum].MessageFormat, PacketSlot, Buff, 1024)) {
	printf("Couldn't apply message to packet\n");
	return FALSE;
    }
    if (!data->Active)
	MysqlDbaseInit(data);

    mixed = sscanf(Buff, "%d.%d.%d.%d:%d->%d.%d.%d.%d:%d",
		   &sa, &sb, &sc, &sd, &src_port,
		   &da, &db, &dc, &dd, &dst_port);

    if (mixed == 10) {
	blob = NULL;
	if (data->LogPackets) {
	    blob =
		(char *) MALLOC((Globals.Packets[PacketSlot].PacketLen * 2) +
				1);
	    if (blob == NULL) {
		printf("FAILED: malloc %d bytes of memory for RawPacket\n",
		       ((Globals.Packets[PacketSlot].PacketLen * 2) + 1));
	    } else {
		mysql_real_escape_string(&data->sql, blob,
					 Globals.Packets[PacketSlot].RawPacket,
					 Globals.Packets[PacketSlot].
					 PacketLen);
	    }
	}
	snprintf(Buff, sizeof(Buff),
		 "INSERT INTO %s(RuleNum,UnixTime,SrcAddress,SrcPort,DstAddress,DstPort,RawPacket) VALUES(%d, %lu, '%d.%d.%d.%d', %d, '%d.%d.%d.%d', %d, '%s')\n",
		 ACTION_ALERT_MYSQL_TABLENAME_ALERT, RuleNum, time(NULL),
		 sa, sb, sc, sd, src_port, da, db, dc, dd, dst_port,
		 (blob != NULL) ? blob : "");
	if (mysql_real_query(&data->sql, Buff, strlen(Buff))) {
	    fprintf(stderr, "Failed Query('%s') = %s\n", Buff,
		    mysql_error(&data->sql));
	}
	FREE_IF(blob);
    }
    return TRUE;
}


/* Shutdown the connection to the MySQL database */
int ActionAlertMysqlShutdownFunc(void *Data)
{
    ActionMysqlRec *data;

    DEBUGPATH;

    if (!Data) {
	DBG((printf("FAILED: %s(%p)\n", __FUNCTION__, Data)));
	return FALSE;
    }

    data = (ActionMysqlRec *) Data;
    DBG((printf("Calling mysql_close(%p)\n", &data->sql)));
    mysql_close(&data->sql);
    data->Active = 0;

    FREE_IF(data->DBase);
    FREE_IF(data->DBUser);
    FREE_IF(data->DBPass);
    FREE_IF(data->DBHost);

    return TRUE;
}


/********************************
* Set up the alert stuff but dont 
* create mysql connection yet.
********************************/
int InitActionAlertMysql()
{
    int ActionID;

    DEBUGPATH;

    ActionID = CreateAction("alert mysql");
    if (ActionID == ACTION_NONE) {
	DBG((printf("Couldn't allocation action alert mysql\n")));
	return FALSE;
    }

    Globals.ActionItems[ActionID].ActionFunc = AlertMysqlAction;
    Globals.ActionItems[ActionID].MessageFunc = AlertMysqlMessage;
    Globals.ActionItems[ActionID].ParseArgs = AlertMysqlParseArgs;

    return TRUE;
}

#endif				/* HAS_MYSQL */
