#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void handle_open_ssl_errors();
int aes_encrypt(unsigned char* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int aes_decrypt(unsigned char* ciphertext, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

#endif
