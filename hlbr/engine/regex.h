/*
 * File: regex.h
 *
 * Description: interface file for regex.c
 *
 * History: 
 *          date - sf login - description
 *
 *          01/18/2006 - morphbr;vivijim - coded this file
 *
 */
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>

// Function to search for a pattern (regular expression) inside a string
// Returns 0 if found
int match(char *string, regex_t *re);
//int match(char *string, char *pattern, regex_t *re);
