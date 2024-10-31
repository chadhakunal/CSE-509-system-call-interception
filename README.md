
# CSE-509 System Call Interception: Transparent Encryption (`secfile`)

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
