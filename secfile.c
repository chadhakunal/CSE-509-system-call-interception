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

// TODO: Fix Read
// TODO: Close
// TODO: Fix encryption
// TODO: Handle writing at random offsets
// TODO: Handle rename, dup, dup2
// TODO: Handle pread and pwrite
// TODO: Handle any other system calls used in gedit, vim, echo, cat firefox 

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
    size_t key_length = 64;  // Assuming a 256-bit (32-byte) key
    size_t key_index;

    for (size_t i = 0; i < length; i++) {
        key_index = (i + offset) % key_length;  // Wrap around the key if needed
        data[i] ^= key[key_index];
    }
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

// void handle_encrypted_read(pid_t child, unsigned long buf_addr, size_t count, unsigned long offset, const unsigned char* key) {
//     // unsigned char buffer[count];

//     // for (size_t i = 0; i < count; i += sizeof(long)) {
//     //     long word = ptrace(PTRACE_PEEKDATA, child, buf_addr + i, NULL);
//     //     if (word == -1) {
//     //         perror("Error reading data from child process");
//     //         return;
//     //     }
//     //     memcpy(buffer + i, &word, sizeof(word));
//     // }

//     // xor_crypt(key, buffer, count, offset);

//     char* tmp = "Hello World";

//     for (size_t i = 0; i < strlen(tmp); i += sizeof(long)) {
//         long word;
//         memcpy(&word, tmp + i, sizeof(word));
//         if (ptrace(PTRACE_POKEDATA, child, buf_addr + i, word) == -1) {
//             perror("Error writing decrypted data to child process");
//             return;
//         }
//     }
// }

// void handle_encrypted_read(pid_t child, unsigned long buf_addr, size_t count, unsigned long offset, const unsigned char* keyT) {
//     const char* message = "Hello World";
//     size_t message_len = strlen(message);

//     // Fill the child's buffer with "Hello World" repeatedly
//     for (size_t i = 0; i < count; i += sizeof(long)) {
//         long word = 0;

//         // Copy up to sizeof(long) bytes from message or zero-fill
//         size_t bytes_to_copy = (i + sizeof(long) <= message_len) ? sizeof(long) : message_len - (i % message_len);
//         memcpy(&word, message + (i % message_len), bytes_to_copy);

//         // Write the modified `word` to the child's buffer at `buf_addr`
//         if (ptrace(PTRACE_POKEDATA, child, buf_addr + i, word) == -1) {
//             perror("Error writing 'Hello World' to child process buffer");
//             return;
//         }
//     }
// }

char* handle_encrypted_read_entry(pid_t child, unsigned long buf_addr, size_t count, unsigned long offset, const unsigned char* key) {
    unsigned char buffer[count];

    for (size_t i = 0; i < count; i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, child, buf_addr + i, NULL);
        if (word == -1) {
            perror("Error reading data from child process");
            return;
        }
        memcpy(buffer + i, &word, sizeof(word));
    }

    xor_crypt(key, buffer, count, offset);
    return buffer;
}

void handle_encrypted_read_exit(char* message, pid_t child, unsigned long buf_addr, unsigned long offset, const unsigned char* key) {
    size_t message_len = strlen(message);

    for (size_t i = 0; i < count; i += sizeof(long)) {
        long word = 0;

        size_t bytes_to_copy = (i + sizeof(long) <= message_len) ? sizeof(long) : message_len - (i % message_len);
        memcpy(&word, message + (i % message_len), bytes_to_copy);

        if (ptrace(PTRACE_POKEDATA, child, buf_addr + i, word) == -1) {
            perror("Error writing 'Hello World' to child process buffer");
            return;
        }
    }
}

void handle_encrypted_write(pid_t child, unsigned long buf_addr, size_t count, unsigned long offset, const unsigned char* key) {
    unsigned char buffer[count];
    for (size_t i = 0; i < count; i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, child, buf_addr + i, NULL);
        memcpy(buffer + i, &word, sizeof(word));
    }

    xor_crypt(key, buffer, count, offset);

    for (size_t i = 0; i < count; i += sizeof(long)) {
        long word;
        memcpy(&word, buffer + i, sizeof(word));
        ptrace(PTRACE_POKEDATA, child, buf_addr + i, word);
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

    char* conf_fd[MAX_FD] = {NULL};
    char* filename = NULL;
    char* read_buffer = NULL;
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
                                conf_fd[fd] = malloc(strlen(filename) + 1);
                                if (conf_fd[fd] == NULL) {
                                    perror("Failed to allocate memory");
                                    exit(1);
                                }
                                strcpy(conf_fd[fd], filename);
                            }
                        }
                    }
                    break;
                
                case SYS_read:
                    if (is_entry) {
                        int fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd] != NULL) {
                            unsigned long buf_addr = regs.rsi;
                            size_t count = regs.rdx;
                            unsigned long offset = regs.r10;

                            if (is_file_encrypted(conf_fd[fd])) {
                                read_buffer = handle_encrypted_read_entry(child, buf_addr, count, offset, encryption_key);
                            } else {
                                printf("read - decrypt for file %s skipped as it is not encrypted", conf_fd[fd]);
                            }
                        }
                    } else {
                        int fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd] != NULL) {
                            unsigned long buf_addr = regs.rsi;
                            size_t count = regs.rdx;
                            unsigned long offset = regs.r10;
                            handle_encrypted_read_entry(read_buffer, child, buf_addr, count, offset, encryption_key);
                        }
                    }
                    break;
                
                case SYS_write:
                    if (is_entry) {
                        int fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd] != NULL) {
                            unsigned long buf_addr = regs.rsi;
                            size_t count = regs.rdx;
                            unsigned long offset = regs.r10;
                            handle_encrypted_write(child, buf_addr, count, offset, encryption_key);
                        }
                    }
                    break;

                case SYS_close:
                    if (!is_entry) {
                        int fd = regs.rdi;
                        if (fd >= 0 && fd < MAX_FD && conf_fd[fd] != NULL) {
                            free(conf_fd[fd]);
                            conf_fd[fd] = NULL;
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
                printf("%s: ", conf_fd[i]);
            }
        }
    }
    free(filename);
    return 0;
}