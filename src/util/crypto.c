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
		
		//printf("inlen: %d %d iv: %d key: %d", strlen(in_str), in_len, strlen(iv), strlen(key));

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
		/*if(pos != strlen(*plaintext))
			printf("\nTHERE IS GOING TO BE AN ERROR!!\n\n");
		else
			printf("no error\n");*/
        EVP_CIPHER_CTX_cleanup(&ctx);
		return pos;
}

int do_digest(char *message, unsigned char **digest)
{
	EVP_MD_CTX *mdctx;	
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i, k=0;

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	EVP_cleanup();
	
	for(i = 0; i < md_len; i++){
        sprintf(*digest+k, "%02x", md_value[i]);
		k += 2;
	}
	return k;
}