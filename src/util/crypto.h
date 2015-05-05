#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

#define ENCRYPT 1
#define DECRYPT 0

int do_crypt(char *in_str, int in_len, int do_encrypt, unsigned char *key,
unsigned char *iv, unsigned char **plaintext);
int do_digest(char *message, unsigned char **digest);

#endif