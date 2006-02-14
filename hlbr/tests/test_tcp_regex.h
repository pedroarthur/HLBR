/*
 * File: test_tcp_regex.h
 *
 * Description: interface file for test_tcp_regex.c
 *
 * History: 
 *          date - sf login - description
 *
 *          01/18/2006 - morphbr;vivijim - coded this file
 *
 */
#ifndef _HLBR_TEST_TCP_RE_H_
#define _HLBR_TEST_TCP_RE_H_

#include "../config.h"
#include "../engine/hlbr.h"
#include "test.h"
#include "../engine/regex.h"

#define MAX_CONTENT_LEN		256

//Function that starts the process of creating this test
int InitTestTCPRegExp();

#endif