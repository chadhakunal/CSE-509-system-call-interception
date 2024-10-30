#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

#include "encryption_util.h"

const char *syscall_names[] = {
    [0] = "read",
    [1] = "write",
    [2] = "open",
    [3] = "close",
    [60] = "exit",
    [57] = "fork"
};

void print_syscall_name(int syscall_num) {
    if (syscall_num >= 0 && syscall_num < sizeof(syscall_names) / sizeof(syscall_names[0]) && syscall_names[syscall_num] != NULL) {
        printf("System call: %s\n", syscall_names[syscall_num]);
    } else {
        printf("Unknown system call: %d\n", syscall_num);
    }
}

int main(int argc, char** argv) {
    if(argc < 4) {
        fprintf(stderr, "Usage: %s <encryption_key> <program> <args>\n", argv[0]);
        return 1;
    }

    char* encryption_key = argv[1];
    char* program_name = argv[2];
    char** program_args = &argv[3];

    printf("Encryption Key: %s\n", encryption_key);
    printf("Program: %s\n", program_name);
    printf("Args: ");
    for(int i = 0; i < argc - 3; i++) {
        printf("%s ", program_args[i]);
    }
    printf("\n");

    pid_t child;
    int status;
    struct user_regs_struct regs;


    unsigned char *plaintext = (unsigned char *)"This is a secret message!";
    unsigned char iv[16];
    
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Random key/IV generation failed\n");
        return 1;
    }

    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    aes_encrypt(plaintext, encryption_key, iv, ciphertext);
    
    aes_decrypt(ciphertext, encryption_key, iv, decryptedtext);
    // decryptedtext[strlen(decryptedtext) - 1] = '\0';
    
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (hex): ");
    for (int i = 0; i < strlen(ciphertext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    // printf("Decrypted text: %s\n", decryptedtext);

    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(program_name, program_args);
    } else {
        waitpid(child, &status, 0);
        while(WIFEXITED(status)) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            int syscall_num = regs.orig_rax;

            print_syscall_name(syscall_num);

            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);
        }
    }

    return 0;
}
