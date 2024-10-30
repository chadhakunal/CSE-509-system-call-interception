#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>
#include <syscall.h>
#include <errno.h>
#include <sys/xattr.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define MAX_FD 4096
#define AES_BLOCK_SIZE 16

void set_secfile_encrypted(const char* filename) {
    const char* attr_name = "user.secfile_encrypted";
    const char* attr_value = "true";
    if (setxattr(filename, attr_name, attr_value, strlen(attr_value), 0) == -1) {
        perror("Error setting secfile_encrypted attribute");
    }
}

bool get_secfile_encrypted(const char* filename) {
    const char* attr_name = "user.secfile_encrypted";
    char attr_value[5] = {0};
    if (getxattr(filename, attr_name, attr_value, sizeof(attr_value)) == -1) {
        if (errno == ENODATA) return false;
        perror("Error getting secfile_encrypted attribute");
        return false;
    }
    return strcmp(attr_value, "true") == 0;
}

void aes_ctr_crypt(const unsigned char* key, unsigned char* data, size_t length, unsigned long offset) {
    AES_KEY aes_key;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char ecount_buf[AES_BLOCK_SIZE] = {0};
    unsigned int num = 0;

    AES_set_encrypt_key(key, 128, &aes_key);
    
    *(unsigned long*)(iv + 8) = offset / AES_BLOCK_SIZE;

    AES_ctr128_encrypt(data, data, length, &aes_key, iv, ecount_buf, &num);
}

char* get_filename(pid_t child, unsigned long addr) {
    char* filename = malloc(4096);
    if (!filename) return NULL;

    int i = 0;
    long word;

    while (i < 4096) {
        word = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (word == -1) {
            perror("ptrace PEEKDATA error");
            free(filename);
            return NULL;
        }
        memcpy(filename + i, &word, sizeof(word));
        if (memchr(&word, 0, sizeof(word)) != NULL) break;
        i += sizeof(word);
    }
    return filename;
}

bool is_conf_file(char* filename) {
    const char* ext = strrchr(filename, '.');
    return ext && strcmp(ext, ".conf") == 0;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <encryption_key> <program> <args>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) != 64) {
        fprintf(stderr, "Error: Encryption key must be exactly 32 bytes (256 bits).\n");
        return 1;
    }

    unsigned char* encryption_key = (unsigned char*)argv[1];
    char* program_name = argv[2];
    char** program_args = &argv[3];

    char* conf_fd[MAX_FD] = {NULL};
    char* filename = NULL;
    struct user_regs_struct regs;
    bool is_entry = false;

    pid_t child;
    int status;

    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(program_name, program_args);
    } else {
        while (1) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break;
            }

            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            int syscall_num = regs.orig_rax;

            switch (syscall_num) {
                case SYS_open:
                case SYS_openat:
                case SYS_creat:
                    if (is_entry) {
                        unsigned long pathname_addr = (syscall_num == SYS_open || syscall_num == SYS_creat) ? regs.rdi : regs.rsi;
                        filename = get_filename(child, pathname_addr);
                    } else {
                        int fd = regs.rax;
                        if (fd >= 0 && fd < MAX_FD) {
                            if (filename != NULL && is_conf_file(filename)) {
                                conf_fd[fd] = filename;
                                set_secfile_encrypted(filename);
                            }
                        }
                    }
                    break;
                    
                default:
                    break;
            }

            is_entry = !is_entry;
        }

        printf("Tracking conf files: \n");
        for(int i = 0; i < MAX_FD; i++) {
            if(conf_fd[i] != NULL) {
                printf("%s (%d)", conf_fd[i], get_secfile_encrypted(conf_fd[i]));
            }
        }
    }
    free(filename);
    return 0;
}