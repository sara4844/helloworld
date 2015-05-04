/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "hash_table.h"
#include "parse_args.h"

typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // Protocol state
	unsigned char key[32];
	HashTable *users;
	int user_count;
	int counter;
} Bank;

//struct used to represent a bank user account
typedef struct User{
	char username[250];
	int balance;
	int pin;
	unsigned char card_key[32];
} User;

Bank* bank_create();
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, unsigned char *command, size_t len);
int get_ascii_arg(char *command, int start, char **arg_out);
int get_letter_arg(char *command, int start, char **arg_out);
int get_digit_arg(char *command, int start,  int *arg_out);

#endif

