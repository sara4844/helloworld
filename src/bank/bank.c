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
	
	FILE *bank_file = fopen(filename, "rb"); 
	if (bank_file == NULL){
		printf("Error opening bank initialization file\n");
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
	bank->users = hash_table_create(100);
	bank->user_count = 0;
	bank->counter = 0;
	bank->user_count++;

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
	
	arg = malloc(251);
	cmd_arg = malloc(251);
	username = malloc(251);
	
	ret = get_ascii_arg(command, pos, &cmd_arg);
	cmd_pos += ret + 1;
	
	if (strcmp(cmd_arg,"create-user") == 0){
		//username
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		if (ret > 0 && ret <= 250){
			pos += ret + 1;
			memcpy(username, arg, ret);
			username[ret]=0;
			
			// pin
			ret = get_digit_arg(command, pos, &int_arg);
			if(ret == 4){
				pos += ret + 1;
				pin = int_arg; 
				
				//balance
				ret = get_digit_arg(command, pos, &int_arg);
				if (ret > 0 && get_ascii_arg(command, pos+ret + 1, &arg) == 0){
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
			printf("Error: user %s already exists\n", username);
			return;
		}
		
		//create user
		new_user = malloc(sizeof(User));
		
		memcpy(new_user->username, username, strlen(username));
		new_user->pin = pin;
		new_user->balance = balance;
		
		//32-string pseudo random printable ascii characters
		for (i=0; i< 32; i++){
			new_user->card_key[i]=(rand() % 94) +32;
		}
		 
		hash_table_add(bank->users, username, new_user);
		bank->user_count++;
		strncpy(card_file_name, username, strlen(username)+1);
		strncat(card_file_name, ".card", strlen(".card"));
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
		memcpy(username, arg, ret);
		username[ret]=0;
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
					else if (get_ascii_arg(command, pos+ret + 1, &arg) == 0){
						input_error = 0;
						user->balance += amt;
						printf("$%d added to %s's account\n", amt, username);
						return;
					}
				}
			} 
		}
		if(input_error == 1){
			printf("Usage:  deposit <user-name> <amt>\n");
		}
	}
	
	//balance
	else if(strcmp(cmd_arg, "balance") == 0){
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		pos += ret + 1;
		memcpy(username, arg, ret);
		username[ret]=0;
		if(ret > 0 && get_ascii_arg(command, pos, &arg) == 0){
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
	return;

}

void bank_process_remote_command(Bank *bank, unsigned char *command, size_t len)
{
    char *arg, *cmd_arg, username[251], message[1025];
	unsigned char sendline[1041 + EVP_MAX_BLOCK_LENGTH];
	unsigned char enc_in[1025], dec_in[1025 + EVP_MAX_BLOCK_LENGTH];
	unsigned char *digest, rec_digest[129], *outbuf, iv[16];
	User *user;
	int ret=0, pos=0, cmd_pos = 0, i=0, int_arg, crypt_len, in_len, digest_len;
	
	arg = malloc(251);
	cmd_arg = malloc(251);
	outbuf = malloc(1025 + EVP_MAX_BLOCK_LENGTH);
	digest = malloc(129);
	
	//clear sendline and outbuf
	sendline[0] = 0;
	outbuf[0] = 0;
	enc_in[0] = 0;
	dec_in[0] = 0;
	
	//first 16 bytes are iv, rest is cipher to decrypt
	memcpy(iv, command, sizeof(iv));
	in_len = len - sizeof(iv);
	memcpy(dec_in, command + sizeof(iv), in_len);
	dec_in[in_len] = 0;
	
	//decrypt cipher
	crypt_len = do_crypt(dec_in, in_len, 0, bank->key, iv, &outbuf);
	
	//first 64 characters are digest, rest is message
	memcpy(rec_digest, outbuf, 128);
	rec_digest[128]=0;
	memcpy(message, outbuf+129, crypt_len - 129);
	message[crypt_len - 129] = 0;
	
	//do_digest on message and verify it matches sent digest
	digest_len = do_digest(message, &digest);
	digest[128]=0;
	if(strcmp(digest, rec_digest) != 0){
		printf("Digests don't match, message was tampered with. Ignoring...\n");
		return;
	}
	
	//check counter
	ret = get_digit_arg(message, cmd_pos, &int_arg);
	cmd_pos += ret + 1;
	
	if(int_arg < bank->counter){
		//Bank got message with an invalid counter. Ignoring...
		return;
	}
	bank->counter = int_arg + 1;
	
	ret = get_ascii_arg(message, cmd_pos, &cmd_arg);
	cmd_pos += ret + 1;
	
	//has form authenticate-user <username>
	if (strcmp(cmd_arg, "authenticate-user")==0){
		pos = cmd_pos;
		ret = get_letter_arg(message, pos, &arg);
		pos += ret + 1;
		memcpy(username, arg, ret);
		username[ret]=0;
		if ((user = hash_table_find(bank->users, username)) != NULL){
			sprintf(message, "%lu found %s %d %s", bank->counter++, user->username, user->pin, user->card_key);
		}
		else{
			sprintf(message, "%lu not-found", bank->counter++);
		}
		
		// Compute Digest
		digest_len = do_digest(message, &digest);
		
		// To encrypt: digest_len digest message
		sprintf(enc_in, "%s %s", digest, message);
		
		//null bytes seem to screw things up so try until no null bytes
		do{
			do{
				RAND_bytes(iv, sizeof(iv));
			} while(strlen(iv) < 16);
			crypt_len = do_crypt(enc_in, strlen(enc_in), 1, bank->key, iv, &outbuf);
		} while (strlen(outbuf) != crypt_len || crypt_len == 0);
		//concat iv and outbuf
		strncat(sendline, iv, sizeof(iv));
		strncat(sendline, outbuf, crypt_len);
		bank_send(bank, sendline, crypt_len + sizeof(iv));
		return;
	}
	
	
	// form withdraw username amt
	else if(strcmp(cmd_arg, "withdraw") == 0){
		//get username
		pos = cmd_pos;
		ret = get_letter_arg(message, pos, &arg);
		pos += ret + 1;
		memcpy(username, arg, strlen(arg));
		user = hash_table_find(bank->users, username);
		
		//get amount
		ret = get_digit_arg(message, pos, &int_arg);
		if(int_arg <= user->balance){
			user->balance -= int_arg;
			sprintf(message, "%lu success", bank->counter++);
		}
		else{
			sprintf(message, "%lu insufficient-funds", bank->counter++);
		}
		
		// Send response
		// Compute Digest
		digest_len = do_digest(message, &digest);
		
		// To encrypt: digest_len digest message
		sprintf(enc_in, "%s %s", digest, message);
		
		//null bytes seem to screw things up so try until no null bytes
		do{
			do{
				RAND_bytes(iv, sizeof(iv));
			} while(strlen(iv) < 16);
			crypt_len = do_crypt(enc_in, strlen(enc_in), 1, bank->key, iv, &outbuf);
		} while (strlen(outbuf) != crypt_len || crypt_len == 0);
		//concat iv and outbuf
		strncat(sendline, iv, sizeof(iv));
		strncat(sendline, outbuf, crypt_len);
		bank_send(bank, sendline, crypt_len + sizeof(iv));
		return;
	}
	
	
	// form balance username
	else if(strcmp(cmd_arg, "balance") == 0){
		//get username
		pos = cmd_pos;
		ret = get_letter_arg(message, pos, &arg);
		pos += ret + 1;
		memcpy(username, arg, strlen(arg));
		user = hash_table_find(bank->users, username);
		
		sprintf(message, "%lu %d", bank->counter++, user->balance);
				
		// Send response
		// Compute Digest
		digest_len = do_digest(message, &digest);
		
		// To encrypt: digest_len digest message
		sprintf(enc_in, "%s %s", digest, message);
		
		//null bytes seem to screw things up so try until no null bytes
		do{
			do{
				RAND_bytes(iv, sizeof(iv));
			} while(strlen(iv) < 16);
			crypt_len = do_crypt(enc_in, strlen(enc_in), 1, bank->key, iv, &outbuf);
		} while (strlen(outbuf) != crypt_len || crypt_len == 0);
		//concat iv and outbuf
		strncat(sendline, iv, sizeof(iv));
		strncat(sendline, outbuf, crypt_len);
		bank_send(bank, sendline, crypt_len + sizeof(iv));
		return;
	}
	
	
	else{
		printf("bank received invalid request\n");
		return;
	}
	
}
