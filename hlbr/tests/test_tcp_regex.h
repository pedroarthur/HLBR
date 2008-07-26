/*
 * File: test_tcp_regex.h
 *
 * Description: interface file for test_tcp_regex.c
 *
 * History: 
 *	date - sf login - description
 *
 *	01/18/2006 - morphbr;vivijim - coded this file
 *	06/26/2007 - arkanoid - replaced posix lib by pcre
 */
#ifndef _HLBR_TEST_TCP_RE_H_
#define _HLBR_TEST_TCP_RE_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "test.h"

#define MAX_CONTENT_LEN		1024

//Function that starts the process of creating this test
int InitTestTCPRegExp();

#endif
