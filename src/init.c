#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

int main(int argc, char**argv)
{

	FILE *bank, *atm;
	FILE *symm_key;
	//unsigned char key[32];
	size_t path_len = 0;
	char bank_filename[255], atm_filename[255];
	//int error = 0, i=0;
	//time_t t;
	//srand((unsigned)time(&t));
	
	char *bank_ext = ".bank", *atm_ext = ".atm";
	
	// user failed to provide just one arg
	if (argc != 2){
		printf("Usage: init <filename>\n");
		return 62;
	}
  
  	/*generate random string
	//TODO: implement this with OpenSSl rand_bytes()? -- I couldn't get this to work
	for (i=0; i< 32; i++){
		key[i]=rand() % 128;
	}*/
  	// get symm_key (I generated a symm key using openssl before hand)
	// TODO: generate a new key beforehand? each time init is called??
	symm_key = fopen("./symm_key.pem", "rb");
	fseek(symm_key, 0, SEEK_END); // seek to end of file
	int symm_key_length = ftell(symm_key) + 1; // get current file pointer
	fseek(symm_key, 0, SEEK_SET); // seek back to beginning of file
	
	unsigned char symm_key_txt[symm_key_length];
	fgets(symm_key_txt, symm_key_length, symm_key);
	fclose(symm_key);
	
	//create filenames
	path_len = strlen(argv[1]);
	strncpy(bank_filename, argv[1], path_len);
	bank_filename[path_len] = 0; 
	strncat(bank_filename, bank_ext, strlen(bank_ext));
	strncpy(atm_filename, argv[1], path_len);
	atm_filename[path_len] = 0;
	strncat(atm_filename, atm_ext, strlen(atm_ext));
	
	//check if either file already exists
	if (access(bank_filename, F_OK) == 0 || access(atm_filename, F_OK) == 0){
		printf("Error: one of the files already exists\n");
		return 63;
	}
	
	//TODO: this only works if the path already exists. 
	// Make the path if doesn't exist.
	
	bank = fopen(bank_filename, "wb");
	atm = fopen(atm_filename, "wb");
	if (bank == NULL && atm == NULL){
		printf("Error creating initialization files\n");
		return 64;
	}
	
	fwrite(symm_key_txt, 1, sizeof(symm_key_txt), bank);
	fwrite(symm_key_txt, 1, sizeof(symm_key_txt), atm);
	fclose(bank);
	fclose(atm);
	
	//else if the program still fails 
	//check if file is successfully created
	if (access(bank_filename, F_OK) != 0 || access(atm_filename, F_OK) != 0){
		printf("Error creating initialization files\n");
		return 64;
	}

	printf("Successfully initialized bank state\n");
	return 0;
}

