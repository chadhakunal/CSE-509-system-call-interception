# CSE 509 - Transparent Encryption
Write a ptrace-based extension that transparently encrypts and decrypts files based on their names. For instance,
using your secfile tool, we should be able to transparently add encryption to the file. This means that when the
file is written, its contents will be encrypted, and when it is read, it will be decrypted. Your tool will be used as
follows:
`secfile⟨program⟩ ⟨args⟩`
where ⟨program⟩ is an arbitrary program, and ⟨args⟩ any arbitrary set of commandline arguments taken by
the program. The behavior of this command should exactly match that of
`⟨program⟩ ⟨args⟩`
except for the transparent encryption of any files with the .conf extension. Note that such a file may or may
not appear among ⟨args⟩.

Managing encryption keys is one of the challenges with encryption, but since that is not the goal of this exercise,
you can use a single alphanumeric key that is passed in as follows:
secfile⟨password⟩ ⟨program⟩ ⟨args⟩
For the purposes of this assignment, it is recommended but not required that you use a proper encryption
algorithm such as AES. However, there will be no penalty if you settle for something very simple such as using the
key to XOR the data in the file.

For this assignment, you only need to handle programs that don’t use lseek, and rely strictly on sequential
access. You also don’t have to handle programs that write back only part of the file.
Your implementation must intercept relevant system calls and modify them as needed to achieve your goal.
Before you start writing code, use strace to identify which system calls you need to handle. For instance, some
applications may use open while others may use openat. You need to handle any and all ways in which files can
be opened.

## Group Members
1. Kunal Chadha (SBU ID: 116714323)
2. Avjot Singh (SBU ID: 116727619)

## How to Build and Run the Application

### Step 1: Generate a Key
Generate a 256-bit encryption key using OpenSSL:
```bash
KEY=$(openssl rand -hex 32)
```

### Step 2: Compile the Application
Use `make` to build the project:
```bash
make
```

### Step 3: Run `secfile` with Your Program
To use `secfile`, pass the generated key along with the program and `.conf` file you want to edit. For example:
```bash
./secfile $KEY nano test.conf
```

### Example Workflow

1. **Encrypting a `.conf` File:**
   - Run `./secfile $KEY nano test.conf` to edit the file in `nano`.
   - Write some text to `test.conf` and save it.
  
2. **Checking Encrypted Content:**
   - Run `cat test.conf` directly to view the file content without `secfile`.
   - You should see encrypted (unreadable) content, as the file is protected.

3. **Decrypting with `secfile`:**
   - Run `./secfile $KEY cat test.conf` to view the file content in plaintext.
   - The encrypted content will be automatically decrypted and displayed.

## Tested Applications
The `secfile` tool has been tested with:
1. `vim`
2. `nano`
3. `cat`
4. `grep`
