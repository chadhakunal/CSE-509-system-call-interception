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
// #include <openssl/aes.h>

#define MAX_FD 4096
#define AES_BLOCK_SIZE 16

size_t fd_offsets[MAX_FD] = {0};

void set_secfile_encrypted(const char* filename) {
    const char* attr_name = "user.secfile_encrypted";
    const char* attr_value = "true";
    if (setxattr(filename, attr_name, attr_value, strlen(attr_value), 0) == -1) {
        perror("Error setting secfile_encrypted attribute");
    }
}

bool is_file_encrypted(const char* filename) {
    const char* attr_name = "user.secfile_encrypted";
    char attr_value[5] = {0};
    if (getxattr(filename, attr_name, attr_value, sizeof(attr_value)) == -1) {
        if (errno == ENODATA) return false;
        perror("Error getting secfile_encrypted attribute");
        return false;
    }
    return strcmp(attr_value, "true") == 0;
}

void xor_crypt(const unsigned char* key, unsigned char* data, size_t length, unsigned long offset) {
    size_t key_length = 32;
    size_t key_index;
    for (size_t i = 0; i < length; i++) {
        key_index = (i + offset) % key_length;
        data[i] ^= key[key_index];
    }
}

// void aes_crypt(const unsigned char* key, unsigned char* data, size_t length, unsigned long offset) {
//     AES_KEY aes_key;
//     if (AES_set_encrypt_key(key, 256, &aes_key) != 0) {
//         fprintf(stderr, "Error setting AES encryption key\n");
//         return;
//     }

//     unsigned char iv[AES_BLOCK_SIZE] = {0};
//     unsigned char ecount_buf[AES_BLOCK_SIZE] = {0};
//     unsigned int num = 0;

//     *(unsigned long*)(iv + 8) = offset / AES_BLOCK_SIZE;

//     AES_ctr128_encrypt(data, data, length, &aes_key, iv, ecount_buf, &num);
// }

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

void handle_encrypted_read(pid_t child, unsigned long buf_addr, size_t count, unsigned long offset, const unsigned char* key) {
    if (count == 0) return;
    unsigned char* buffer = malloc(count);
    if (buffer == NULL) {
        perror("Failed to allocate memory for read buffer");
        return;
    }
    for (size_t i = 0; i < count; i++) {
        long byte = ptrace(PTRACE_PEEKDATA, child, buf_addr + i, NULL);
        if (byte == -1) {
            perror("Error reading data from child process");
            free(buffer);
            return;
        }
        buffer[i] = (unsigned char)byte;
    }
    xor_crypt(key, buffer, count, offset);
    for (size_t i = 0; i < count; i++) {
        if (ptrace(PTRACE_POKEDATA, child, buf_addr + i, (void*)(long)buffer[i]) == -1) {
            perror("Error writing modified data to child process buffer");
            free(buffer);
            return;
        }
    }
    free(buffer);
}

void handle_encrypted_write(pid_t child, unsigned long buf_addr, size_t count, unsigned long offset, const unsigned char* key) {
    unsigned char buffer[count];
    for (size_t i = 0; i < count; i++) {
        long byte = ptrace(PTRACE_PEEKDATA, child, buf_addr + i, NULL);
        if (byte == -1) {
            perror("Error reading data from child process");
            return;
        }
        buffer[i] = (unsigned char)byte;
    }
    xor_crypt(key, buffer, count, offset);
    for (size_t i = 0; i < count; i++) {
        if (ptrace(PTRACE_POKEDATA, child, buf_addr + i, (void*)(long)buffer[i]) == -1) {
            perror("Error writing modified data to child process buffer");
            return;
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <encryption_key> <program> [args...]\n", argv[0]);
        return 1;
    }
    if (strlen(argv[1]) != 64) {
        fprintf(stderr, "Error: Encryption key must be exactly 64 characters.\n");
        return 1;
    }

    unsigned char* encryption_key = (unsigned char*)argv[1];
    char* program_name = argv[2];
    char** program_args = &argv[2]; 

    char* conf_fd[MAX_FD] = {NULL};
    char* filename = NULL;
    unsigned long read_buf_addr;
    int fd;
    struct user_regs_struct regs;
    bool is_entry = false;

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(program_name, program_args);
        perror("execvp failed");
        exit(1);
    } else {
        int status;
        while (1) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) break;

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
                        fd = regs.rax;
                        if (fd >= 0 && fd < MAX_FD) {
                            if (filename != NULL && is_conf_file(filename)) {
                                conf_fd[fd] = malloc(strlen(filename) + 1);
                                if (conf_fd[fd] == NULL) {
                                    perror("Failed to allocate memory");
                                    exit(1);
                                }
                                strcpy(conf_fd[fd], filename);
                                fd_offsets[fd] = 0;
                            }
                        }
                    }
                    break;

                case SYS_read:
                    if (is_entry) {
                        fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd]) {
                            read_buf_addr = regs.rsi;
                        }
                    } else {
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd] && is_file_encrypted(conf_fd[fd])) {
                            handle_encrypted_read(child, read_buf_addr, regs.rax, fd_offsets[fd], encryption_key);
                            fd_offsets[fd] += regs.rax;
                        }
                    }
                    break;

                case SYS_write:
                    if (is_entry) {
                        fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd]) {
                            unsigned long buf_addr = regs.rsi;
                            size_t count = regs.rdx;
                            handle_encrypted_write(child, buf_addr, count, fd_offsets[fd], encryption_key);
                            set_secfile_encrypted(conf_fd[fd]);
                            fd_offsets[fd] += count;
                        }
                    }
                    break;
                
                case SYS_pread64:
                    if (is_entry) {
                        fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd]) {
                            read_buf_addr = regs.rsi;
                        }
                    } else {
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd] && is_file_encrypted(conf_fd[fd])) {
                            unsigned long offset = regs.r10;
                            handle_encrypted_read(child, read_buf_addr, regs.rax, offset, encryption_key);
                        }
                    }
                    break;

                case SYS_pwrite64:
                    if (is_entry) {
                        fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd]) {
                            unsigned long buf_addr = regs.rsi;
                            size_t count = regs.rdx;
                            unsigned long offset = regs.r10;
                            handle_encrypted_write(child, buf_addr, count, offset, encryption_key);
                            set_secfile_encrypted(conf_fd[fd]);
                        }
                    }
                    break;

                case SYS_close:
                    if (!is_entry) {
                        fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd]) {
                            free(conf_fd[fd]);
                            conf_fd[fd] = NULL;
                            fd_offsets[fd] = 0;
                        }
                    }
                    break;

                default:
                    break;
            }
            is_entry = !is_entry;
        }
    }
    free(filename);
    return 0;
}