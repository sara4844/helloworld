#include "bank.h"
#include "ports.h"
#include "hash_table.h"
#include "parse_args.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/evp.h>


Bank* bank_create(char *filename)
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
	
	// printf("%s\n", filename);
	FILE *bank_file = fopen(filename, "rb"); 
	if (bank_file == NULL){
		printf("Error opening Bank initialization file\n");
		return 64;
	}
	
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    
	// Read the symmetric key from file and store in mem 
	fread(bank->key, 1, 32, bank_file);
	//printf("%s\n", bank->key);
	
	//set up hash table to store users
	//TODO: be able to resize hash if reaches limit
	bank->users = hash_table_create(100); 

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
	char card_file_name[255];
	char username[250], *cmd_arg, *arg;
	int input_error = 1, pin, ret, cmd_pos = 0, pos = 0, i =0, amt, int_arg;
	long int balance;
	User new_user, *user;
	FILE *card_file;
	time_t t;
	srand((unsigned)time(&t));
	
	arg = malloc(250 * sizeof(char));
	cmd_arg = malloc(250 * sizeof(char));
	
	ret = get_ascii_arg(command, pos, &cmd_arg);
	cmd_pos += ret+1;
	//printf("ret: %d new pos: %d\n", ret, pos);
	
	if (strcmp(cmd_arg,"create-user") == 0){
		//username
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		//printf("ret: %d \n", ret);
		if (ret > 0 && ret <= 250){
			pos += ret+1;
			memcpy(username, arg, strlen(arg)+1);
			//printf("username: %s\n", username);
			
			// pin
			ret = get_digit_arg(command, pos, &int_arg);
			//printf("ret: %d \n", ret);
			if(ret == 4){
				pos += ret+1;
				//printf("ret: %d new pos: %d\n", ret, pos);
				pin = int_arg; //safe because already checked are digits
				//printf("PIN: %d\n", pin);
				//balance
				ret = get_digit_arg(command, pos, &int_arg);
				if (ret > 0 && get_ascii_arg(command, pos+ret+1, &arg) == 0){
					balance = int_arg;
					//printf("balance: %d\n", balance);
					input_error = 0;
				}
			}
		}
		if (input_error) {
			printf("Usage: create-user <user-name> <pin> <balance>\n");
			return;
		}
		
		//check if user exists
		if (hash_table_find(bank->users, username) != NULL){
			printf("Error: user %s alread exists\n", username);
			return;
		}
		
		//create user
		//printf("making new user\n");
		memcpy(new_user.username, username, sizeof(username));
		//printf("%s\n",new_user.username);
		new_user.pin = pin;
		new_user.balance = balance;
		for (i=0; i< 32; i++){
			new_user.card_key[i]=rand() % 128; //no, not perfectly distributed but good enough?
		}
		 
		hash_table_add(bank->users, username, &new_user);
		strncpy(card_file_name, username, strlen(username)+1);
		strncat(card_file_name, ".card", strlen(".card"));
		//printf("%s\n", card_file_name);
		card_file = fopen(card_file_name, "wb");
		if(card_file != NULL){
			ret = fwrite(new_user.card_key, 1, sizeof(new_user.card_key), card_file);
			fclose(card_file);
			if (ret == sizeof(new_user.card_key)){
				printf("Created user %s\n", username);
				return;
			}
		}
		printf("Error creating card file for user %s\n", username);

	}
	
	//Deposit
	else if (strcmp(cmd_arg, "deposit") == 0){
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		if(ret > 0){
			if((user = hash_table_find(bank->users, arg)) == NULL){
				printf("No such user\n");
				return;
			}
			else{
				pos += ret + 1;
				ret = get_digit_arg(command, pos, &int_arg);
				if(ret > 0){
					amt = int_arg;
					if (amt + user->balance < user->balance){
						printf("Too rich for this program\n");
						return;
					}
					else if (get_ascii_arg(command, pos+ret+1, &arg) == 0){
						input_error = 0;
						user->balance += amt;
						printf("$%d added to %s's account\n", amt, username);
						return;
					}
				}
				if(input_error == 1){
					
					printf("Usage:  deposit <user-name> <amt>\n");
				}
			}
		}
	}
	
	//balance
	else if(strcmp(cmd_arg, "balance") == 0){
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		if(ret > 0){
			if((user = hash_table_find(bank->users, arg)) == NULL){
				printf("No such user\n");
				return;
			}
			else{
				printf("$%d\n", user->balance);
				return;
			}
		}
		printf("Usage:  balance <user-name>\n");
	}
	else
		printf("Invalid command\n");
	
	free(arg);
	free(cmd_arg);

}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
	time_t t = time(NULL);
    // TODO: Implement the bank side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply receives a
	 * string from the ATM, prepends "Bank got: " and echoes 
	 * it back to the ATM before printing it to stdout.
	 */
	 
    char sendline[1000];
    command[len]=0;
    sprintf(sendline, "Bank got: %s", command);
    bank_send(bank, sendline, strlen(sendline));
    printf("Received the following:\n");
    fputs(command, stdout);
	
}
