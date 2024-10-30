#include "encryption_util.h"

void handle_open_ssl_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) 
        handle_open_ssl_errors();
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) 
        handle_open_ssl_errors();
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext)) != 1) 
        handle_open_ssl_errors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) 
        handle_open_ssl_errors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    int len;
    int plaintext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!ctx)
        handle_open_ssl_errors();
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) 
        handle_open_ssl_errors();
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) 
        handle_open_ssl_errors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handle_open_ssl_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
