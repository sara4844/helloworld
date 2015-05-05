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
    time_t t;
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
	atm->current_username = NULL;
	atm->counter = 0;
	atm->failed_attempts = 0;
	atm->fail_time = time(&t);
	printf("init time is: %d\n", atm->fail_time);

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
	char username[250], *cmd_arg, *arg, user_card_filename[256], pin_in[10], message[1024];
	char cardkey[33], username_cardkey[33];
	int input_error = 1, username_pin, pin, ret, cmd_pos = 0, pos = 0, amt, int_arg, n;
	int crypt_len, in_len, digest_len;
	User *current_user;
	FILE *card;
	time_t t;
	
	cmd_arg = malloc(251);
	arg = malloc(251);
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
			sprintf(message, "%d authenticate-user %s",atm->counter++, username);
			
			// Compute Digest
			digest_len = do_digest(message, &digest);
			
			// To encrypt: digest_len digest message
			sprintf(enc_in, "%s %s", digest, message);
			
			//null bytes seem to screw things up so try until no null bytes
			do{
				do{
					RAND_bytes(iv, sizeof(iv));
				} while(strlen(iv) < 16);
				crypt_len = do_crypt(enc_in, strlen(enc_in), 1, atm->key, iv, &outbuf);
			} while (strlen(outbuf) != crypt_len || crypt_len == 0);
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
				return;
			}
			
			//check counter
			pos = 0;
			ret = get_digit_arg(message, pos, &int_arg);
			pos += ret+1;
			if(int_arg < atm->counter){
				printf("atm got message with an invalid counter! Ignoring...\n");
				return;
			}
			if(int_arg != atm->counter)
				printf("a packet was dropped...\n");
			atm->counter = int_arg + 1;
			printf("ATM got counter %d, ATM counter now: %d\n", atm->counter);
			
			//process response
			ret = get_ascii_arg(message, pos, &arg);
			if(ret<= 0 ){
				//shouldn't happen bc verifying signature but just in case
				return;
			}
			else{
				if(strcmp("found", arg) == 0){
					pos += ret;
					//username
					atm->current_username = malloc(251);
					ret = get_letter_arg(message, pos, &arg);
					pos += ret+1;
					strncpy(atm->current_username, arg, strlen(arg));
					atm->current_username[strlen(arg)]=0;
					
					//pin
					ret = get_digit_arg(message, pos, &int_arg);
					pos += ret+2;
					username_pin = int_arg;
					
					//card
					//ret = get_ascii_arg(message, pos, &arg);
					//pos += ret+1;
					memcpy(username_cardkey, message+pos, 32);
					username_cardkey[32]=0;
					//printf("user's card key: %s %d %d\n", username_cardkey, sizeof(username_cardkey), strlen(username_cardkey));
					//look for the card file and check can read
					sprintf(user_card_filename,"%s.card", atm->current_username);
					card = fopen(user_card_filename, "r");
					if(card == NULL){
						printf("unable to access %s's card\n", atm->current_username);
						return;
					}
					ret = fread(cardkey, 1, sizeof(cardkey), card);
					cardkey[32]=0;
					//printf("read cardkey: %s\n", cardkey);
					if(strncmp(cardkey, username_cardkey, sizeof(username_cardkey)) != 0){
						printf("unable to access %s's card - cardkey mismatch\n", atm->current_username);
						return;
					}				 
					
					
					//prompt for pin
					printf("PIN? ");
					fgets(pin_in, 10, stdin);
					pos = 0;
					ret = get_digit_arg(pin_in, pos, &int_arg);
					pin = int_arg;
					pos += ret + 1;
					if(pin != username_pin || get_ascii_arg(pin_in, pos, &arg)){
						printf("Not Authorized\n");
						
						//check for 3 failed attempts in 30 seconds - lock for 30 seconds (10 for testing)
						if((time(&t) - atm->fail_time) <= 30){
							printf("fail within 30 secs\n");
							if(atm->failed_attempts >= 2){
								printf("3 failed login attempts. Wait 30 seconds before trying again\n");
								sleep(10);
							}
							else{
								atm->failed_attempts++;
								printf("%d failed attempts\n",atm->failed_attempts);
							}
							return;
						}
						//if not within 30 seconds reset fail counter
						else{
							atm->failed_attempts = 1;
							atm->fail_time = time(&t);
							printf("resetting: attempts: %d time: %d", atm->failed_attempts, atm->fail_time);
						}
							
						
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
	
	
	//Withdraw
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
					
				// Write message
				sprintf(message, "%d withdraw %s %d",atm->counter++, atm->current_username, amt);
				
				// Compute Digest
				digest_len = do_digest(message, &digest);
				
				// To encrypt: digest_len digest message
				sprintf(enc_in, "%s %s", digest, message);
				
				//null bytes seem to screw things up so try until no null bytes
				do{
					do{
						RAND_bytes(iv, sizeof(iv));
					} while(strlen(iv) < 16);
					crypt_len = do_crypt(enc_in, strlen(enc_in), 1, atm->key, iv, &outbuf);
				} while (strlen(outbuf) != crypt_len || crypt_len == 0);
				//concat iv and outbuf
				strncat(sendline, iv, sizeof(iv));
				strncat(sendline, outbuf, crypt_len);
				atm_send(atm, sendline, crypt_len + sizeof(iv));
					
				
				//process response from bank
				n = atm_recv(atm,recvline, 1024);
				recvline[n]=0;
				
				//clear sendline and outbuf
				outbuf[0] = 0;
				dec_in[0] = 0;
				
				//first 16 bytes are iv, rest is cipher to decrypt
				memcpy(iv, recvline, sizeof(iv));
				in_len = n - sizeof(iv);
				memcpy(dec_in, recvline + sizeof(iv), in_len);
				dec_in[in_len] = 0;
				
				//decrypt cipher
				crypt_len = do_crypt(dec_in, in_len, 0, atm->key, iv, &outbuf);
				
				//first 64 characters are digest, rest is message
				memcpy(rec_digest, outbuf, 128);
				memcpy(message, outbuf+129, crypt_len - 129);
				message[crypt_len - 129] = 0;
				
				//do_digest on message and verify it matches sent digest
				digest_len = do_digest(message, &digest);
				if(strcmp(digest, rec_digest) != 0){
					printf("Digests don't match!\n");
					//TODO: what to do here?
					return -1;
				}
				
				//check counter
				pos = 0;
				ret = get_digit_arg(message, pos, &int_arg);
				pos += ret+1;
				if(int_arg < atm->counter){
					printf("atm got message with an invalid counter! Ignoring...\n");
					return;
				}
				if(int_arg != atm->counter)
					printf("a packet was dropped...\n");
				atm->counter = int_arg + 1;
				printf("ATM got counter %d, ATM counter now: %d\n", atm->counter);
				
				//process response
				ret = get_ascii_arg(message, pos, &arg);
				
				if(strcmp(arg, "success") == 0)
					printf("$%d dispensed\n", amt);
				else if (strcmp(arg, "insufficient-funds") == 0)
					printf("Insufficient funds\n");
				else
					printf("error\n");
				return;
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
		
		// Write message
		sprintf(message, "%d balance %s",atm->counter++, atm->current_username);
		
		// Compute Digest
		digest_len = do_digest(message, &digest);
		
		// To encrypt: digest_len digest message
		sprintf(enc_in, "%s %s", digest, message);
		
		//null bytes seem to screw things up so try until no null bytes
		do{
			do{
				RAND_bytes(iv, sizeof(iv));
			} while(strlen(iv) < 16);
			crypt_len = do_crypt(enc_in, strlen(enc_in), 1, atm->key, iv, &outbuf);
		} while (strlen(outbuf) != crypt_len || crypt_len == 0);
		//concat iv and outbuf
		strncat(sendline, iv, sizeof(iv));
		strncat(sendline, outbuf, crypt_len);
		atm_send(atm, sendline, crypt_len + sizeof(iv));
			
		
		//process response from bank
		n = atm_recv(atm,recvline, 1024);
		recvline[n]=0;
		
		//clear sendline and outbuf
		outbuf[0] = 0;
		dec_in[0] = 0;
		
		//first 16 bytes are iv, rest is cipher to decrypt
		memcpy(iv, recvline, sizeof(iv));
		in_len = n - sizeof(iv);
		memcpy(dec_in, recvline + sizeof(iv), in_len);
		dec_in[in_len] = 0;
		
		//decrypt cipher
		crypt_len = do_crypt(dec_in, in_len, 0, atm->key, iv, &outbuf);
		
		//first 64 characters are digest, rest is message
		memcpy(rec_digest, outbuf, 128);
		memcpy(message, outbuf+129, crypt_len - 129);
		message[crypt_len - 129] = 0;
		
		//do_digest on message and verify it matches sent digest
		digest_len = do_digest(message, &digest);
		if(strcmp(digest, rec_digest) != 0){
			printf("Digests don't match!\n");
			//TODO: what to do here?
			return -1;
		}
		
		//check counter
		pos = 0;
		ret = get_digit_arg(message, pos, &int_arg);
		pos += ret+1;
		if(int_arg < atm->counter){
			printf("atm got message with an invalid counter! Ignoring...\n");
			return;
		}
		if(int_arg != atm->counter)
			printf("a packet was dropped...\n");
		atm->counter = int_arg + 1;
		
		//process response
		ret = get_digit_arg(message, pos, &int_arg);
		
		
		printf("$%d\n", int_arg);
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
		
		free(atm->current_username);
		atm->current_username = NULL;
		atm->logged_in = 0;
		printf("User logged out\n");
		return;
			
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
