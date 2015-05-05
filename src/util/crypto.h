#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>


int encrypt(char *message, unsigned char *key, unsigned char **ret);
int do_crypt(char *in_str, int in_len, int do_encrypt, unsigned char *key,
unsigned char *iv, unsigned char **plaintext);
int do_digest(char *message, unsigned char **digest);

#endif