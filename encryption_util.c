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


// unsigned char *plaintext = (unsigned char *)"This is a secret message!";
// unsigned char iv[16];

// if (!RAND_bytes(iv, 16)) {
//     fprintf(stderr, "Random key/IV generation failed\n");
//     return 1;
// }

// unsigned char ciphertext[128];
// unsigned char decryptedtext[128];

// int ciphertext_len = aes_encrypt(plaintext, key, iv, ciphertext);

// int decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
// decryptedtext[decryptedtext_len] = '\0';

// printf("Plaintext: %s\n", plaintext);
// printf("Ciphertext (hex): ");
// for (int i = 0; i < ciphertext_len; i++) {
//     printf("%02x", ciphertext[i]);
// }
// printf("\n");

// printf("Decrypted text: %s\n", decryptedtext);


// const char *syscall_names[] = {
//     [0] = "read",
//     [1] = "write",
//     [2] = "open",
//     [3] = "close",
//     [60] = "exit",
//     [57] = "fork"
// };

// void print_syscall_name(int syscall_num) {
//     if (syscall_num >= 0 && syscall_num < sizeof(syscall_names) / sizeof(syscall_names[0]) && syscall_names[syscall_num] != NULL) {
//         printf("System call: %s\n", syscall_names[syscall_num]);
//     } else {
//         printf("Unknown system call: %d\n", syscall_num);
//     }
// }