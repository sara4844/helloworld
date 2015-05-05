#include "atm.h"
#include "ports.h"
#include "bank.h"
#include "parse_args.h"
#include "crypto.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>




ATM* atm_create(char *filename)
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
	FILE *atm_file = fopen(filename, "rb"); 
	if (atm_file == NULL){
		printf("Error opening ATM initialization file\n");
		exit(64);
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
	atm->current_user = NULL;
	atm->counter = 0;

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
	unsigned char recvline[1024 + EVP_MAX_BLOCK_LENGTH], sendline[1040 + EVP_MAX_BLOCK_LENGTH];
	unsigned char enc_in[1024], dec_in[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char *digest, rec_digest[128], *outbuf, iv[16];
	char username[250], *cmd_arg, *arg, user_card_filename[255], pin_in[10], message[1024];
	int input_error = 1, pin, ret, cmd_pos = 0, pos = 0, amt, int_arg, n;
	int crypt_len, in_len, digest_len;
	User *current_user;
	//time_t t;
	
	cmd_arg = malloc(250);
	arg = malloc(255);
	current_user = malloc(sizeof(User));
	outbuf = malloc(1024 + EVP_MAX_BLOCK_LENGTH);
	digest = malloc(128);
	
	//clear sendline and outbuf
	sendline[0] = 0;
	outbuf[0] = 0;
	enc_in[0] = 0;
	dec_in[0] = 0;
	
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
			
			//should be no more args
			if(get_ascii_arg(command, pos, &arg) != 0){
				printf("Usage:  begin-session <user-name>\n");
				return;
			}
			
			//send request to bank for User username
			// Write message
			sprintf(message, "%d get-user %s",atm->counter++, username);
			
			// Compute Digest
			digest_len = do_digest(message, &digest);
			//printf("digest %d\n", digest_len);
			
			// To encrypt: digest_len digest message
			sprintf(enc_in, "%s %s", digest, message);
			//printf("%s %d\n", enc_in, sizeof(enc_in));
			
			//null bytes seem to screw things up so try until no null bytes
			do{
				do{
					RAND_bytes(iv, sizeof(iv));
				} while(strlen(iv) < 16);
				crypt_len = do_crypt(enc_in, strlen(enc_in), 1, atm->key, iv, &outbuf);
			} while (strlen(outbuf) != crypt_len || crypt_len == 0);
			//printf("outbuf: %d\n", crypt_len);
			//concat iv and outbuf
			strncat(sendline, iv, sizeof(iv));
			strncat(sendline, outbuf, crypt_len);
			atm_send(atm, sendline, crypt_len + sizeof(iv));
			
			//process response from bank
			n = atm_recv(atm,recvline, 1024);
			recvline[n]=0;
			
			//clear sendline and outbuf
			sendline[0] = 0;
			outbuf[0] = 0;
			enc_in[0] = 0;
			dec_in[0] = 0;
			
			
			//first 16 bytes are iv, rest is cipher to decrypt
			memcpy(iv, recvline, sizeof(iv));
			in_len = n - sizeof(iv);
			memcpy(dec_in, recvline + sizeof(iv), in_len);
			dec_in[in_len] = 0;
			
			//decrypt cipher
			crypt_len = do_crypt(dec_in, in_len, 0, atm->key, iv, &outbuf);
			//printf("outbuf: %s\n", outbuf);
			
			//first 64 characters are digest, rest is message
			memcpy(rec_digest, outbuf, 128);
			memcpy(message, outbuf+129, crypt_len - 129);
			message[crypt_len - 129] = 0;
			printf("%s\n", message);
			
			//do_digest on message and verify it matches sent digest
			digest_len = do_digest(message, &digest);
			//printf("%s\n", digest);
			if(strcmp(digest, rec_digest) != 0){
				printf("Digests don't match!\n");
				//TODO: what to do here?
				return -1;
			}
			
			//check counter
			pos = 0;
			ret = get_digit_arg(message, pos, &int_arg);
			pos += ret+1;
			printf("atm received counter %d\n", int_arg);
			if(int_arg < atm->counter){
				printf("atm got message with an invalid counter! Ignoring...\n");
				return;
			}
			if(int_arg != atm->counter)
				printf("a packet was dropped...\n");
			atm->counter = int_arg + 1;
			printf("atm's counter now: %d\n", atm->counter);
			
			//process response
			ret = get_ascii_arg(message, pos, &arg);
			if(ret<= 0 ){
				//shouldn't happen bc verifying signature but just in case
				//printf("invalid response received.\n");
				return;
			}
			else{
				if(strcmp("found", arg) == 0){
					pos += ret;
					//username
					ret = get_letter_arg(message, pos, &arg);
					pos += ret+1;
					strncpy(current_user->username, arg, strlen(arg));
					current_user->username[strlen(arg)]=0;
					
					//balance
					ret = get_digit_arg(message, pos, &int_arg);
					pos += ret+1;
					current_user->balance = int_arg;
					
					//pin
					ret = get_digit_arg(message, pos, &int_arg);
					pos += ret+1;
					current_user->pin = int_arg;
					
					//look for the card file and check can read
					sprintf(user_card_filename,"%s.card", current_user->username);
					if (access(user_card_filename, R_OK) != 0) {
						printf("unable to access %s's card\n", current_user->username);
						return;
					}
					
					//prompt for pin
					printf("PIN? ");
					fgets(pin_in, 10, stdin);
					pos = 0;
					ret = get_digit_arg(pin_in, pos, &int_arg);
					pin = int_arg;
					pos += ret + 1;
					if(pin != current_user->pin || get_ascii_arg(pin_in, pos, &arg)){
						printf("Not Authorized\n");
						return;
					}
					
					else{
						printf("Authorized\n");
						atm->logged_in=1;
						atm->current_user = current_user;
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
		
		//get amt from user input
		pos = cmd_pos;
		ret = get_digit_arg(command, pos, &int_arg);
		if (ret > 0){
			amt = int_arg;
			pos += ret+1;
			//should be no more args
			if(get_ascii_arg(command, pos, &arg) == 0){
				if (amt<= atm->current_user->balance){
					atm->current_user-> balance -= int_arg;
					printf("$%d dispensed\n", amt);
					return;
				}
				else{
					printf("Insufficient funds\n");
					return;
				}
			}
			
		}
		printf("Usage:  withdraw <amt>\n");
		return;
		
	}
	
	else if (strcmp(cmd_arg, "balance") == 0){
		if(!atm->logged_in){
			printf("No user logged in\n");
			return;
		}
		pos = cmd_pos;
		if (get_ascii_arg(command, pos, &arg) != 0){
			printf("Usage:  balance\n");
			return;
		}
		
		printf("$%d\n", atm->current_user->balance);
		return;
	}
	
	// Must send balance update back to bank. User cannot succussefully log out until
	// atm recieves confirmation from bank that balance has been updated. Resend until
	// get confirmation
	else if (strcmp(cmd_arg, "end-session") == 0){
		if(!atm->logged_in){
			printf("No user logged in\n");
			return;
		}
		
		//should be no more args
		pos = cmd_pos;
		if(get_ascii_arg(command, pos, &arg) != 0){
			printf("Usage:  end-session\n");
			return;
		}
		
		sprintf(message, "%d update-balance %s %d", atm->counter++, atm->current_user->username, atm->current_user->balance);
		
		// Compute Digest
		digest_len = do_digest(message, &digest);
		//printf("digest %d\n", digest_len);
		
		// To encrypt: digest_len digest message
		sprintf(enc_in, "%s %s", digest, message);
		//printf("%s %d\n", enc_in, sizeof(enc_in));
		
		//null bytes seem to screw things up so try until no null bytes
		do{
			do{
				RAND_bytes(iv, sizeof(iv));
			} while(strlen(iv) < 16);
			crypt_len = do_crypt(enc_in, strlen(enc_in), 1, atm->key, iv, &outbuf);
		} while (strlen(outbuf) != crypt_len || crypt_len == 0);
		//printf("outbuf: %d\n", crypt_len);
		//concat iv and outbuf
		strncat(sendline, iv, sizeof(iv));
		strncat(sendline, outbuf, crypt_len);
		
		atm_send(atm, sendline, crypt_len + sizeof(iv));
		
		
		//process response from bank
		n = atm_recv(atm,recvline,10000);
		recvline[strlen(recvline)]=0;
		
		//clear sendline and outbuf
		sendline[0] = 0;
		outbuf[0] = 0;
		enc_in[0] = 0;
		dec_in[0] = 0;
		
		//first 16 bytes are iv, rest is cipher to decrypt
		memcpy(iv, recvline, sizeof(iv));
		in_len = n - sizeof(iv);
		memcpy(dec_in, recvline + sizeof(iv), in_len);
		dec_in[in_len] = 0;
		
		//decrypt cipher
		crypt_len = do_crypt(dec_in, in_len, 0, atm->key, iv, &outbuf);
		//printf("outbuf: %s\n", outbuf);
		
		//first 64 characters are digest, rest is message
		memcpy(rec_digest, outbuf, 128);
		memcpy(message, outbuf+129, crypt_len - 129);
		message[crypt_len - 129] = 0;
		printf("%s\n", message);
		
		//do_digest on message and verify it matches sent digest
		digest_len = do_digest(message, &digest);
		//printf("%s\n", digest);
		if(strcmp(digest, rec_digest) != 0){
			printf("Digests don't match!\n");
			//TODO: what to do here?
			return -1;
		}
		
		//check counter
		pos = 0;
		ret = get_digit_arg(message, pos, &int_arg);
		pos += ret+1;
		printf("atm received counter %d\n", int_arg);
		if(int_arg < atm->counter){
			printf("atm got message with an invalid counter! Ignoring...\n");
			return;
		}
		if(int_arg != atm->counter)
			printf("a packet was dropped...\n");
		atm->counter = int_arg + 1;
		printf("atm's counter now: %d\n", atm->counter);
			
		//process response
		ret = get_ascii_arg(message, pos, &arg);
		if(ret<= 0 ){
			//shouldn't happen bc verifying signature but just in case
			//printf("invalid response received.\n");
			return;
		}
		else{
			if(strcmp("success", arg) == 0){
				//free(atm->current_user);
				atm->current_user = NULL;
				atm->logged_in = 0;
				printf("User logged out\n");
				return;
			}
			else {
				printf("something went wrong, resend\n");
			}
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
