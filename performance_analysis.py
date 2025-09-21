"""
performance_analysis.py
Measures AES-128 CFB encryption/decryption performance on a 1MB text file.
Records encryption time, decryption time, and ciphertext size.
"""
import time
from cfb_mode import aes_cfb_encrypt, aes_cfb_decrypt
from main import hex_to_bytes

# Settings
KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"  # Example 128-bit key
IV_HEX = "000102030405060708090a0b0c0d0e0f"    # Example IV
INPUT_FILE = "input_1mb.txt"  # Path to 1MB text file

# Read file as bytes
def read_file_bytes(filename):
    with open(filename, "rb") as f:
        return list(f.read())

# Write bytes to file
def write_file_bytes(filename, data):
    with open(filename, "wb") as f:
        f.write(bytes(data))

if __name__ == "__main__":
    print("AES-128 CFB Performance Analysis")
    # Prepare key and IV
    key_bytes = hex_to_bytes(KEY_HEX)
    iv_bytes = hex_to_bytes(IV_HEX)
    # Read input file
    plaintext = read_file_bytes(INPUT_FILE)
    print(f"Plaintext size: {len(plaintext)} bytes")
    # Encrypt
    start_enc = time.time()
    ciphertext = aes_cfb_encrypt(plaintext, key_bytes, iv_bytes)
    end_enc = time.time()
    enc_time = end_enc - start_enc
    write_file_bytes("ciphertext.bin", ciphertext)
    # Decrypt
    start_dec = time.time()
    recovered = aes_cfb_decrypt(ciphertext, key_bytes, iv_bytes)
    end_dec = time.time()
    dec_time = end_dec - start_dec
    write_file_bytes("recovered.txt", recovered)
    # Results table
    print("\nResults:")
    print("+-------------------+-------------------+")
    print("| Operation         | Time (seconds)    |")
    print("+-------------------+-------------------+")
    print(f"| Encryption        | {enc_time:.6f}        |")
    print(f"| Decryption        | {dec_time:.6f}        |")
    print("+-------------------+-------------------+")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print("\nTable for report:")
    print("| Operation   | Time (s)   | Size (bytes) |")
    print(f"| Encrypt     | {enc_time:.6f} | {len(ciphertext)}        |")
    print(f"| Decrypt     | {dec_time:.6f} | {len(recovered)}        |")
    print("\nCheck 'ciphertext.bin' and 'recovered.txt' for output files.")
