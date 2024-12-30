# Multi-Layer Program Security Analysis and Reverse Engineering

## Project Overview
This project implements a multi-layered security challenge designed to test reverse engineering skills. The program consists of three distinct layers of protection, each requiring different analysis techniques to bypass. The implementation demonstrates various anti-analysis techniques and obfuscation methods commonly found in real-world software protection schemes.

## Protection Layers

### Layer 1: Stream Cipher Encryption
- Password encryption using a stream cipher
- PRNG-based encryption sequence
- Key discovery requires reverse engineering of PRNG setup
- Decryption process depends on reconstructing the random sequence

### Layer 2: Dynamic Password Generation
- Password dynamically generated during runtime
- XOR transformation of pre-defined strings
- Password fragments distributed across system files
- Time-dependent password reconstruction
- Order of fragment combination varies based on system time

### Layer 3: Runtime Binary Modification
- Dynamic modification of function behavior during execution
- Encryption operations modified to their inverse operations
- Password provided as integer sequence
- Decryption logic hidden in runtime state
- Requires understanding of binary patching techniques

## Anti-Analysis Features & Red Herrings

### System Protection Mechanisms
- Time-based shutdown triggers
- Debugger detection shutdown
- Root privilege requirements
- Multiple anti-debugging checks
- Interrupt handler for file cleanup

### Obfuscation Techniques
- System call scrambling using encrypted strings
- Movie-based function name obfuscation
- False network connectivity checks
- Deceptive file operations
- Misleading steganography implementation
- Irrelevant SHA256 hash implementation
- Dummy functions returning constants
- Deceptive image generation code

## Requirements
- Linux-based operating system
- Root privileges (sudo access)
- OpenSSL development libraries
- G++ compiler
- Make utility

## Building and Running

### Compilation
To compile the project, navigate to the project directory and run the following command:

```bash
make
```

This will use the `makefile` to build the project. Ensure that you have the required dependencies installed, including the OpenSSL development libraries and the G++ compiler.

If you want to clean up the compiled files, you can run:

```bash
make clean
```

## Technical Implementation
- Written in C++
- Uses OpenSSL cryptographic libraries
- Implements various system calls for security checks
- Multiple layers of key verification
- Complex obfuscation techniques

## Project Structure
- `C2.cpp`: Main program implementation
- `makefile`: Build configuration

## Educational Purpose
This project demonstrates advanced software protection techniques and serves as a practical exercise in reverse engineering. It showcases various anti-analysis methods and highlights the importance of thorough binary analysis when approaching protected software.

## License
[Your chosen license]