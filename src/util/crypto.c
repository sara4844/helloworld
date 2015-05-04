#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"

int do_crypt(char *in_str, int in_len, int do_encrypt, unsigned char *key, unsigned char *iv, 
unsigned char **plaintext)
{
        unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH],
            crypted[1024];
        int inlen, outlen, pos=0, in_str_len=0;
        EVP_CIPHER_CTX ctx;

        EVP_CIPHER_CTX_init(&ctx);
        EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, NULL, NULL,
                do_encrypt);
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 32);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);
		
        EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
                inlen = strlen(in_str);
				
                if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, in_str, in_len))
                {
                   printf("error\n");
                   EVP_CIPHER_CTX_cleanup(&ctx);
                   return 0;
               }
                strncpy(crypted+pos, outbuf, outlen);
                pos += outlen;
            //    printf("pos: %d outlen: %d\n", pos, outlen);


        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
        {
				printf("final error\n");
                return 0;
        }

        strncpy(crypted + pos, outbuf, outlen);
        pos += outlen;
        crypted[pos] = 0;
        memcpy(*plaintext, crypted, pos+1);
		if(pos != strlen(*plaintext))
			//printf("\nTHERE IS GOING TO BE AN ERROR!!\n\n");

        EVP_CIPHER_CTX_cleanup(&ctx);

        return pos;
}

/*
int main(){

  FILE *words_file, *plaintext_file, *cipher;
  unsigned char plaintext[1024] = "This is top secret.", *ret, cipher_str[1024];
  char *line;
  size_t len;
  ssize_t read;
  unsigned char key[32], iv[16];

  RAND_bytes(key, sizeof(key));
  RAND_bytes(key, sizeof(iv));

  
  
  ret = malloc(1024 * sizeof(char));


        
        printf("plaintext: %s\n", plaintext);


        do_crypt(plaintext, 1, key, iv, &ret);
        printf("%d ret: \n%s\n", strlen(ret), ret);
        memcpy(cipher_str, ret, strlen(ret));
        cipher_str[strlen(ret)] = 0;
        printf("now decrypting\n");
        do_crypt(cipher_str, 0, key, iv, &ret);
        printf("ret: %s\n", ret);




}
*/
