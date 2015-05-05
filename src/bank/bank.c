#include "bank.h"
#include "ports.h"
#include "hash_table.h"
#include "parse_args.h"
#include "crypto.h"
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
		exit(64);
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
	
	//set up hash table to store users
	//TODO: be able to resize hash if reaches limit
	bank->users = hash_table_create(1000);
	bank->user_count = 0;
	bank->counter = 0;

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
	char * username, *cmd_arg, *arg;
	int input_error = 1, pin, ret, cmd_pos = 0, pos = 0, i =0, amt, int_arg;
	long int balance;
	User *new_user, *user;
	FILE *card_file;
	time_t t;
	srand((unsigned)time(&t));
	
	arg = malloc(255 * sizeof(char));
	cmd_arg = malloc(250 * sizeof(char));
	username = malloc(250*sizeof(char));
	
	ret = get_ascii_arg(command, pos, &cmd_arg);
	cmd_pos += ret+1;
	
	if (strcmp(cmd_arg,"create-user") == 0){
		//username
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		if (ret > 0 && ret <= 250){
			pos += ret+1;
			memcpy(username, arg, strlen(arg));
			username[strlen(arg)]=0;
			
			// pin
			ret = get_digit_arg(command, pos, &int_arg);
			if(ret == 4){
				pos += ret+1;
				pin = int_arg; 
				
				//balance
				ret = get_digit_arg(command, pos, &int_arg);
				if (ret > 0 && get_ascii_arg(command, pos+ret+1, &arg) == 0){
					balance = int_arg;
					input_error = 0;
				}
			}
		}
		if (input_error) {
			printf("Usage:  create-user <user-name> <pin> <balance>\n");
			return;
		}
		
		//check if user exists
		if (hash_table_find(bank->users, username) != NULL){
			printf("Error: user %s alread exists\n", username);
			return;
		}
		
		//create user
		new_user = malloc(sizeof(User));
		
		memcpy(new_user->username, username, strlen(username));
		new_user->pin = pin;
		new_user->balance = balance;
		for (i=0; i< 32; i++){
			new_user->card_key[i]=rand() % 128;
		}
		 
		hash_table_add(bank->users, username, new_user);
		strncpy(card_file_name, username, strlen(username)+1);
		strncat(card_file_name, ".card", strlen(".card"));
		//printf("%s\n", card_file_name);
		card_file = fopen(card_file_name, "wb");
		if(card_file != NULL){
			ret = fwrite(new_user->card_key, 1, sizeof(new_user->card_key), card_file);
			fclose(card_file);
			if (ret == sizeof(new_user->card_key)){
				printf("Created user %s\n", username);
				bank->user_count++;
				return;
			}
		}
		printf("Error creating card file for user %s\n", username);

	}
	
	//Deposit
	else if (strcmp(cmd_arg, "deposit") == 0){
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		memcpy(username, arg, strlen(arg));
		username[strlen(arg)]=0;
		if(ret > 0){
			if((user = hash_table_find(bank->users, username)) == NULL){
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
		memcpy(username, arg, strlen(arg));
		username[strlen(arg)]=0;
		if(ret > 0){
			if((user = hash_table_find(bank->users, username)) == NULL){
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

void bank_process_remote_command(Bank *bank, unsigned char *command, size_t len)
{
    char *arg, *cmd_arg, username[250], message[1024];
	unsigned char sendline[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char enc_in[1024], dec_in[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char *digest, rec_digest[128], *outbuf, iv[16];
	User *user;
	int ret=0, pos=0, cmd_pos = 0, i=0, int_arg, crypt_len, in_len, digest_len;
	
	arg = malloc(250);
	cmd_arg = malloc(250);
	outbuf = malloc(1024 + EVP_MAX_BLOCK_LENGTH);
	digest = malloc(128);
	
	//clear sendline and outbuf
	sendline[0] = 0;
	outbuf[0] = 0;
	enc_in[0] = 0;
	dec_in[0] = 0;
	
	//first 16 bytes are iv, rest is cipher to decrypt
	memcpy(iv, command, sizeof(iv));
	in_len = len - sizeof(iv);
	memcpy(dec_in, command + sizeof(iv), in_len);
	dec_in[len - sizeof(iv)] = 0;
	
	//decrypt cipher
	crypt_len = do_crypt(dec_in, in_len, 0, bank->key, iv, &outbuf);
	printf("outbuf: %s %d\n", outbuf, strlen(outbuf));
	
	//first 64 characters are digest, rest is message
	memcpy(rec_digest, outbuf, 128);
	memcpy(message, outbuf+129, crypt_len - 129);
	printf("%s\n%s\n", rec_digest, message);
	
	//do_digest on message and verify it matches sent digest
	digest_len = do_digest(message, &digest);
	printf("%s\n", digest);
	if(strcmp(digest, rec_digest) != 0){
		printf("Digests don't match!\n");
	}
	
	//check counter
	ret = get_digit_arg(message, cmd_pos, &int_arg);
	cmd_pos += ret+1;
	//printf("received counter %d\n", int_arg);
	
	if(int_arg < bank->counter){
		printf("Bank got message with an invalid counter! Ignoring...\n");
		return;
	}
	if(int_arg != bank->counter){
		printf("a packet was dropped...\n");
	}
	bank->counter = int_arg + 1;
	//printf("banks's counter now: %d\n", bank->counter);
	
	ret = get_ascii_arg(message, cmd_pos, &cmd_arg);
	cmd_pos += ret+1;
	
	//has form get-user <username>
	if (strcmp(cmd_arg, "get-user")==0){
		pos = cmd_pos;
		ret = get_letter_arg(message, pos, &arg);
		//bank already checked valid username
		pos += ret+1;
		memcpy(username, arg, strlen(arg));
		username[strlen(arg)]=0;
		if ((user = hash_table_find(bank->users, username)) != NULL){
			sprintf(enc_in, "%d found %s %d %d", bank->counter++, user->username, user->balance, user->pin);
			//bank_send(bank, sendline, strlen(sendline));
		}
		else{
			//user doesn't exist
			sprintf(enc_in, "%d not-found", bank->counter++);
			//bank_send(bank, "not-found", sizeof("not-found"));
		}
		
		//encrypt message and send
		//TODO: sign
		//printf("encrypting: %s\n", enc_in);
	
		do{
			do{
				RAND_bytes(iv, sizeof(iv));
				//printf("iv: %d\n", strlen(iv));
			} while(strlen(iv) < 16);		
			crypt_len = do_crypt(enc_in, strlen(enc_in), 1, bank->key, iv, &outbuf);
			//printf("outbuf: %d crypt_len %d\n", strlen(outbuf), crypt_len);
		} while (strlen(outbuf) != crypt_len || crypt_len == 0);
		
		
		strncat(sendline, iv, sizeof(iv));
		strncat(sendline, outbuf, crypt_len);
		//printf("sending: %d\n", crypt_len + sizeof(iv)); 
		bank_send(bank, sendline, crypt_len + sizeof(iv));
		return;
	}
	
	// has form update-balance <username> <balance>
	else if (strcmp(cmd_arg, "update-balance")==0){
		pos = cmd_pos;
		ret = get_letter_arg(message, pos, &arg);
		//atm already checked valid username
		pos += ret+1;
		memcpy(username, arg, strlen(arg));
		username[strlen(arg)]=0;
		if ((user = hash_table_find(bank->users, username)) != NULL){
			ret = get_digit_arg(message, pos, &int_arg);
			//printf("%s's balance updated from %d ", username, user->balance);
			user->balance = int_arg;
			//printf("to %d\n", user->balance);
			sprintf(enc_in, "%d success", bank->counter++);
			
			//encrypt message and send
			//printf("encrypting: %s\n", enc_in);
			do{
				do{
					RAND_bytes(iv, sizeof(iv));
					//printf("iv: %d\n", strlen(iv));
				} while(strlen(iv) < 16);
				crypt_len = do_crypt(enc_in, strlen(enc_in), 1, bank->key, iv, &outbuf);
				//printf("outbuf: %d crypt_len %d\n", strlen(outbuf), crypt_len);
			} while (strlen(outbuf) != crypt_len || crypt_len == 0);
			
			
			strncat(sendline, iv, sizeof(iv));
			strncat(sendline, outbuf, crypt_len);
			//printf("sending: %d\n", crypt_len + sizeof(iv)); 
			bank_send(bank, sendline, crypt_len + sizeof(iv));
			return;
		
		}
		printf("error\n");
		//bank_send(bank, "error", strlen("error"));
	}
	
	else{
		printf("bank received invalid request\n");
		//bank_send(bank, "error", strlen("error"));
		return;
	}
	
	
	/*
    sprintf(sendline, "Bank got: %s", command);
    bank_send(bank, sendline, strlen(sendline));
    printf("Received the following:\n");
    fputs(command, stdout);*/
	
}
