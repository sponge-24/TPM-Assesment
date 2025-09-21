# AES-128 CFB Mode Implementation

## Overview
This project implements AES-128 encryption and decryption in CFB (Cipher Feedback) mode from scratch in Python, without using any external cryptography libraries. The code is modular and well-commented for clarity and learning purposes.

## Files
- `main.py`: User interface for encryption/decryption.
- `sbox.py`: S-box and inverse S-box tables, SubBytes functions.
- `key_expansion.py`: Key expansion logic.
- `aes_core.py`: AES block operations (AddRoundKey, ShiftRows, MixColumns).
- `cfb_mode.py`: CFB mode encryption/decryption logic.
- `performance_analysis.py`: Measures encryption/decryption speed and output size for a 1MB file.

## How to Run
1. Run `main.py` to encrypt/decrypt text using AES-128 CFB mode.
2. Run `performance_analysis.py` to measure performance on a 1MB file.

## Task 2: Mode-Specific Security Analysis (CFB Mode)

### Block Dependencies
In CFB mode, each ciphertext block depends on the previous ciphertext block. The encryption of each plaintext block uses the output of the AES block cipher applied to the previous ciphertext (or IV for the first block). This means that changing one block of ciphertext will affect the decryption of the current and next block, creating a chain of dependencies.

### Initial Vector (IV)/Nonce Usage
CFB mode requires an IV (initialization vector) for the first block. The IV must be unique and unpredictable for each encryption session to ensure security. If the same IV is reused with the same key, it can lead to vulnerabilities. In this implementation, the IV can be generated randomly using the current timestamp if not provided by the user.

### Error Propagation
If a single bit in a ciphertext block is corrupted, only the corresponding plaintext block and the next block will be affected during decryption. The error does not propagate further, so the rest of the plaintext remains correct. This is different from some other modes (like CBC), where errors can affect all subsequent blocks.

## Example Table (Performance)
| Operation   | Time (s)   | Size (bytes) |
|-------------|------------|--------------|
| Encrypt     | 0.123456   | 1048576      |
| Decrypt     | 0.098765   | 1048576      |

## References
- NIST FIPS 197: Advanced Encryption Standard (AES)
- Project source code and comments

---
For any questions or clarifications, please refer to the code comments or contact the author.
