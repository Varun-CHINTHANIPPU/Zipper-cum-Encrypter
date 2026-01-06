## Zipper cum Encrypter
A multi-threaded Java application that provides secure file encryption and compression using AES-256-CBC encryption with PBKDF2 key derivation. The tool recursively processes directories, encrypting files and organizing them into compressed archives while maintaining the original folder structure.

### Features
- Strong Encryption: AES-256-CBC encryption with PBKDF2-HMAC-SHA256 key derivation (65,536 iterations)
- Parallel Processing: Multi-threaded execution utilizing all available CPU cores for faster processing
- Recursive Directory Handling: Automatically processes entire directory trees while preserving structure
- Secure Random Generation: Uses SecureRandom for salt and IV generation
- Bidirectional Operation: Supports both encryption/compression and decryption/decompression
- Metadata Preservation: Stores encryption parameters (salt, IV) with each encrypted file

### Technical Specifications
Encryption Algorithm
- Cipher: AES (Advanced Encryption Standard)
- Mode: CBC (Cipher Block Chaining)
- Padding: PKCS5Padding
- Key Size: 256 bits
- Key Derivation: PBKDF2WithHmacSHA256
- Iterations: 65,536
- Salt Length: 16 bytes (128 bits)
- IV Length: 16 bytes (128 bits)

### Performance
- Thread pool size dynamically matches available processor cores
- Buffered I/O streams for optimized file operations
- Timeout mechanism prevents indefinite hanging (10-minute processing limit)

### Requirements
- Java Development Kit (JDK) 11 or higher
- Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files (included by default in JDK 8u161+)

### Installation
Clone or download the repository
Compile the source code:
```
javac Zipper.java
```
### Usage
Encryption Mode
Encrypt and compress all files in a directory:
```
java Zipper /path/to/folder
The program will prompt for a password. Encrypted files will be stored in /path/to/folder_processed/ with the structure:
Each subdirectory becomes a separate .zip archive
Files are encrypted and saved with .enc extension inside the archives
Root-level files are stored in root.zip
```
Decryption Mode
```
To decrypt, simply run the tool on a folder containing .zip or .enc files with the same password used during encryption.
```
### Security Considerations
Strengths
- Uses industry-standard AES-256 encryption
- PBKDF2 with 65,536 iterations makes brute-force attacks computationally expensive
- Unique salt and IV for each file prevents pattern analysis
- SecureRandom ensures cryptographically strong randomness

Limitations
- Password is stored in memory as a String (cannot be securely wiped)
- No authentication mechanism (HMAC) to verify data integrity
- Password is entered via console (visible in process list on some systems)
- No secure password validation or strength requirements

### File Format
Each encrypted file in the ZIP archive follows this structure:
```
[16 bytes: Salt][16 bytes: IV][Variable: Encrypted Data]
```

Workflow
Encrypting Files
```
project/
├── src/
│   ├── Main.java
│   └── Utils.java
└── config.xml

project_processed/
├── src.zip          
└── root.zip
```   
Decrypting Files
```
java Zipper project_processed

project_processed/
├── src/
│   ├── Main.java
│   └── Utils.java
└── config.xml
```
### Error Handling
- The tool includes error handling for:
- Invalid command-line arguments
- File I/O failures
- Encryption/decryption errors
- Directory creation failures
- Thread interruptions
- Error messages are printed to stderr with specific failure context.

### Troubleshooting
Problem: "Illegal key size" exception
Solution: Ensure you're using JDK 8u161+ or have JCE Unlimited Strength installed

Problem: Processing hangs indefinitely
Solution: The tool has a 10-minute timeout; check for very large files or system resource constraints

Problem: Decryption fails with "Bad padding" error
Solution: Verify you're using the correct password; this error indicates password mismatch

### Future Enhancements
- Add HMAC for authenticated encryption (encrypt-then-MAC)
- Implement progress bar for large file operations
- Add command-line options for configurable iteration count
- Support for password files or environment variables
- Memory-safe password handling with char arrays
- Compression before encryption for reduced file size
