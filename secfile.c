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

char* conf_fd[MAX_FD] = {NULL};

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

void trace(pid_t child, bool is_entry, unsigned char* encryption_key, char* tmp_data) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    int syscall_num = regs.orig_rax;

    switch (syscall_num) {
        case SYS_open:
        case SYS_openat:
        case SYS_creat:
            if (is_entry) {
                unsigned long pathname_addr = (syscall_num == SYS_open || syscall_num == SYS_creat) ? regs.rdi : regs.rsi;
                tmp_data = get_filename(child, pathname_addr);
                if (tmp_data != NULL && is_conf_file(tmp_data)) {
                    printf("Tracking conf file: %s!\n", tmp_data);
                }
            } else {
                int fd = regs.rax;
                if (fd >= 0 && fd < MAX_FD) conf_fd[fd] = tmp_data;
            }
            break;
            
        default:
            break;
    }
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

    char* tmp_data;

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

            if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
                printf("SYSTEM CALL ENTERED!");
            }

            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break;
            }

            if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
                giprintf("SYSTEM CALL EXIT!");
            }
        }
        
        // waitpid(child, &status, 0);
        // while (WIFSTOPPED(status)) {
        //     // Entry
        //     ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        //     waitpid(child, &status, 0);
        //     trace(child, true, &encryption_key, &tmp_data);

        //     // Exit
        //     ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        //     waitpid(child, &status, 0);
        //     trace(child, false, &encryption_key, &tmp_data);
        // }
    }

    free(tmp_data);

    return 0;
}