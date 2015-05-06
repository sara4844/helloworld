#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>


#define C_IS_LETTER (c >= 65 && c <=90 ) || (c >=97 && c <=122)
#define C_IS_DIGIT c >=48 && c <=57
#define C_IS_ASCII c >= 0 && c <= 127

//Reads in one space delimited user input argument. Checks if valid ascii character
// Returns length of arg read or 0 if no args to read
int get_ascii_arg(char *command, int start, char **arg_out){
	int pos = start, arg_pos = 0;
	char arg[251], c;
	
	if(start >= strlen(command))
		return 0;	

	while ((c = command[pos++]) != 0 && !isspace(c)){
		if(!(C_IS_ASCII))
			return -1;
		if(arg_pos >= 250){
			return -1;					
		}
		arg[arg_pos++] = c;
	}
	arg[arg_pos] = '\0';
	memcpy(*arg_out, arg, arg_pos+1);

	return arg_pos;
}

//Reads in one space delimited user input argument. Checks if valid ascii character
// Returns length of arg read or 0 if no args to read
int get_letter_arg(char *command, int start, char **arg_out){
	int pos = start, arg_pos = 0;
	char arg[251], c;
	
	if(start >= strlen(command))
		return 0;	

	while ((c = command[pos++]) != 0 && !isspace(c)){
		if(!(C_IS_LETTER))
			return -1;
		if(arg_pos >= 250){
			return -1;					
		}
		arg[arg_pos++] = c;
	}
	arg[arg_pos] = '\0';
	memcpy(*arg_out, arg, arg_pos+1);

	return arg_pos;
}

//Reads in one space delimited user input argument. Checks if valid ascii character
// Returns length of arg read or 0 if no args to read
int get_digit_arg(char *command, int start, int *arg_out){
	int pos = start, arg_pos = 0;
	char arg[11], c, *end;
	unsigned long long_arg;
	
	if(start >= strlen(command))
		return 0;	

	while(!isspace(c = command[pos++]) && c !=0){
		if(!(C_IS_DIGIT)){
			return -1;
		}
		if(arg_pos > 10){
			return -1;					
		}
		arg[arg_pos++] = c;
	}
	arg[arg_pos] = '\0';
	long_arg = strtoul(arg, &end, 10);
	if (long_arg < 0 || long_arg > INT_MAX)
		return -1;
	else
		*arg_out = (int) long_arg;
			
	return arg_pos;
}