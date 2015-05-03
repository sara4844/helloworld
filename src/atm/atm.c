#include "atm.h"
#include "ports.h"
#include "bank.h"
#include "parse_args.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdio.h>
#include <limits.h>
#include <ctype.h>
#include <openssl/evp.h>




ATM* atm_create(char *filename)
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
	FILE *atm_file = fopen(filename, "rb"); 
	if (atm_file == NULL){
		printf("Error opening ATM initialization file\n");
		return 64;
	}
	
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
	fread(atm->key, 1, 32, atm_file);
    atm->logged_in = 0;
	atm->current_user = malloc(sizeof(User));

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{
	char recvline[10000], sendline[1000];

	char username[250], *cmd_arg, *arg, *response, user_card_filename[255], pin_in[10];
	int input_error = 1, pin, ret, cmd_pos = 0, pos = 0, i =0, amt, int_arg, n;
	int balance;
	User current_user;
	FILE *card_file;
	time_t t;
	srand((unsigned)time(&t));
	
	arg = malloc(250 * sizeof(char));
	cmd_arg = malloc(250 * sizeof(char));
	
	ret = get_ascii_arg(command, pos, &cmd_arg);
	cmd_pos += ret+1;
	
	if (strcmp(cmd_arg, "begin-session") == 0){
		//get username
		if(atm->logged_in){
			printf("A user is already logged in\n");
			return;
		}
		
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		if (ret > 0 && ret <= 250){
			pos += ret+1;
			memcpy(username, arg, strlen(arg)+1);
			
			//send request to bank for User username
			// TODO encrypt and add counter/timestamp
			sprintf(sendline, "get-user %s", username);
			printf("sending: %s\n", sendline);
			atm_send(atm, sendline, strlen(sendline));
			n = atm_recv(atm,recvline,10000);
			recvline[n]=0;
			printf("atm got: %s\n",recvline);
			
			//process response from bank
			
			//TODO Decrypt and verify signature - signature means don't have to check for valid inputs
			//because we know message bank sent wasn't tampered with
			pos = 0;
			ret = get_ascii_arg(recvline, pos, &arg);
			if(ret<= 0 ){
				//shouldn't happen but just in case
				printf("invalid response received.\n");
				return;
			}
			else{
				if(strcmp("found", arg) == 0){
					pos += ret;
					//username
					ret = get_letter_arg(recvline, pos, &arg);
					pos += ret+1;
					strncpy(current_user.username, arg, strlen(arg));
					current_user.username[strlen(arg)]=0;
					
					//balance
					ret = get_digit_arg(recvline, pos, &int_arg);
					pos += ret+1;
					current_user.balance = int_arg;
					
					//pin
					ret = get_digit_arg(recvline, pos, &int_arg);
					pos += ret+1;
					current_user.pin = int_arg;
					
					printf("username: %s balance: %d pin: %d\n", current_user.username, current_user.balance, current_user.pin);
					
					//look for the card file and check can read
					sprintf(user_card_filename,"%s.card", current_user.username);
					if (access(user_card_filename, R_OK) != 0) {
						printf("unable to access %s's card\n", current_user.username);
						return;
					}
					
					//prompt for pin
					printf("PIN? ");
					fgets(pin_in, 10, stdin);
					pos = 0;
					ret = get_digit_arg(pin_in, pos, &int_arg);
					if(int_arg != current_user.pin){
						printf("Not Authorized\n");
						return;
					}
					
					else{
						printf("Authorized\n");
						atm->logged_in=1;
						strncpy(atm->current_user->username,current_user.username, sizeof(current_user.username));
						atm->current_user->pin = current_user.pin;
						atm->current_user->balance = current_user.balance;
						return;
					}
					
					
				}
				else if(strcmp("not-found", arg) == 0){
					printf("No such user\n");
					return;
				}
			}
			
		}
		else{
			printf("Usage:  begin-sesion <user-name>\n");
		}
	}
	
	else if (strcmp(cmd_arg, "withdraw") == 0){
		if(!atm->logged_in){
			printf("No user logged in\n");
			return;
		}
		
		
	}
	
	else if (strcmp(cmd_arg, "balance") == 0){
		if(!atm->logged_in){
			printf("No user logged in\n");
			return;
		}
	}
	
	else{
		printf("Invalid command\n");
	}
	
	/*
    atm_send(atm, command, strlen(command));
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    fputs(recvline,stdout);
	//printf("atm time: %ld\n", t);
	*/
	
}
