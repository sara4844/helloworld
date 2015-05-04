/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main(int argc, char**argv)
{
    char user_input[300];
	time_t t;
	
    ATM *atm;
	if ((atm = atm_create(argv[1])) == 64) return 64;
    
    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 300, stdin) != NULL)
	{
		atm_process_command(atm, user_input);
		if (atm->logged_in){
			printf("ATM (%s):", atm->current_user->username);
		}
		else{
			printf("%s", prompt);
		}
		fflush(stdout);
    }
	return EXIT_SUCCESS;
}
