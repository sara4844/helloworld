#include "atm.h"
#include "ports.h"
#include "bank.h"
#include "parse_args.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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
    // TODO set up more, as needed

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

	char username[250], *cmd_arg, *arg;
	int input_error = 1, pin, ret, cmd_pos = 0, pos = 0, i =0, amt, int_arg;
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
		pos = cmd_pos;
		ret = get_letter_arg(command, pos, &arg);
		if (ret > 0 && ret <= 250){
			pos += ret+1;
			memcpy(username, arg, strlen(arg)+1);
		}
		else{
			printf("Usage:  begin-sesion <user-name>\n");
		}
	}
	
	else if (strcmp(cmd_arg, "withdraw") == 0){
		
	}
	
	else if (strcmp(cmd_arg, "balance") == 0){
		
	}
	
	else{
		printf("Invalid command");
	}
	
	/*
    atm_send(atm, command, strlen(command));
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    fputs(recvline,stdout);
	//printf("atm time: %ld\n", t);
	*/
	
}
