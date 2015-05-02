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
	
    ATM *atm = atm_create(argv[1]);

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 300, stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        printf("%s", prompt);
        fflush(stdout);
    }
	return EXIT_SUCCESS;
}
