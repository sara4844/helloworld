/*
 * This provides methods for reading in one space delimited user input
 */

#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>

int get_ascii_arg(char *command, int start, char **arg_out);
int get_letter_arg(char *command, int start, char **arg_out);
int get_digit_arg(char *command, int start,  int *arg_out);


#endif
