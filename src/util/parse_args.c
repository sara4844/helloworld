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
	char arg[250], c;

	while ( (c = command[pos++]) != 0){
		if(!isspace(c)){
			if(!(C_IS_ASCII))
				return -1;
			arg_pos = 0;
			arg[arg_pos++] = c;
			while(!isspace(c = command[pos++])){
				if(!(C_IS_ASCII))
					return -1;
				if(arg_pos > 250){
					printf("arg too long\n");
					return -1;					
				}
				arg[arg_pos++] = c;
			}
			arg[arg_pos] = '\0';
			memcpy(*arg_out, arg, arg_pos+1);
			break;
		}
	}
	return arg_pos;
}

//Reads in one space delimited user input argument. Checks if valid ascii character
// Returns length of arg read or 0 if no args to read
int get_letter_arg(char *command, int start, char **arg_out){
	int pos = start, arg_pos = 0;
	char arg[250], c;
	
	while ( (c = command[pos++]) != 0){
		if(!isspace(c)){
			if(!(C_IS_LETTER)){
				printf("not a letter\n");
				return -1;
			}
			arg_pos = 0;
			arg[arg_pos++] = c;
			while(!isspace(c = command[pos++])){
				if(!(C_IS_LETTER)){
					printf("not a letter\n");
					return -1;
				}
				if(arg_pos > 250){
					printf("arg too long\n");
					return -1;					
				}
				arg[arg_pos++] = c;
			}
			arg[arg_pos] = '\0';
			memcpy(*arg_out, arg, arg_pos+1);
			break;
		}
	}
	return arg_pos;
}

//Reads in one space delimited user input argument. Checks if valid ascii character
// Returns length of arg read or 0 if no args to read
int get_digit_arg(char *command, int start, int *arg_out){
	int pos = start, arg_pos = 0;
	char arg[11], c, *end;
	long int long_arg;
	
	
	while ( (c = command[pos++]) != 0){
		if(!isspace(c)){
			if(!(C_IS_DIGIT)){
				printf("not a digit\n");
				return -1;
			}
			arg_pos = 0;
			arg[arg_pos++] = c;
			while(!isspace(c = command[pos++])){
				if(!(C_IS_DIGIT)){
					printf("not a digit\n");
					return -1;
				}
				if(arg_pos > 10){
					//printf("arg too long\n");
					return -1;					
				}
				arg[arg_pos++] = c;
			}
			arg[arg_pos] = '\0';
			//printf("  arg: %s\n", arg);
			//TODO: strtol returns INT_MAX if number is > INT_MAX - fix this
			long_arg = strtol(arg, &end, 10);
			//printf("long_arg: %d\n", long_arg);
			if (long_arg < 0 || long_arg > INT_MAX)
				return -1;
			else
				*arg_out = (int) long_arg;
			break;
		}
	}
	return arg_pos;
}