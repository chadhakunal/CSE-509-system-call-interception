#include "encryption_util.h"

void handle_open_ssl_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void aes_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) 
        handle_open_ssl_errors();
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) 
        handle_open_ssl_errors();
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext)) != 1) 
        handle_open_ssl_errors();

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) 
        handle_open_ssl_errors();

    EVP_CIPHER_CTX_free(ctx);
}

void aes_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!ctx)
        handle_open_ssl_errors();
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) 
        handle_open_ssl_errors();
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, strlen((char *)ciphertext)) != 1) 
        handle_open_ssl_errors();
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handle_open_ssl_errors();
    
    EVP_CIPHER_CTX_free(ctx);
}
