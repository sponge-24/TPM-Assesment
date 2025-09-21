"""
main.py
Main program for AES-128 CFB mode encryption and decryption from scratch.
Accepts plaintext, key, and IV from user, runs encryption/decryption, and verifies output.
"""
from cfb_mode import aes_cfb_encrypt, aes_cfb_decrypt

# Helper: Convert hex string to byte array
def hex_to_bytes(hex_str):
    """
    Converts hex string to byte array.
    """
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

# Helper: Convert string to byte array
def str_to_bytes(s):
    """
    Converts ASCII string to byte array.
    """
    return [ord(c) for c in s]

# Helper: Convert byte array to string
def bytes_to_str(b):
    """
    Converts byte array to ASCII string.
    """
    return ''.join(chr(x) for x in b)

if __name__ == "__main__":
    print("AES-128 CFB Mode Encryption/Decryption (from scratch)")
    # Get plaintext
    plaintext = input("Enter plaintext: ")
    pt_bytes = str_to_bytes(plaintext)
    # Get key (hex string, 32 chars for 128 bits)
    key_hex = input("Enter 128-bit key (hex, 32 chars): ")
    key_bytes = hex_to_bytes(key_hex)
    if len(key_bytes) != 16:
        print("Key must be 16 bytes (32 hex chars)")
        exit(1)
    # Get IV (hex string, 32 chars for 128 bits). If blank, generate from timestamp.
    import time
    iv_hex = input("Enter IV (hex, 32 chars) [leave blank to auto-generate]: ")
    if iv_hex.strip() == "":
        # Generate IV using current timestamp
        ts = int(time.time() * 1000000)  # microseconds for more entropy
        iv_bytes = [(ts >> (8 * i)) & 0xff for i in range(16)]
        print("Generated IV (hex):", ''.join(f'{b:02x}' for b in iv_bytes))
    else:
        iv_bytes = hex_to_bytes(iv_hex)
        if len(iv_bytes) != 16:
            print("IV must be 16 bytes (32 hex chars)")
            exit(1)
    # Pad plaintext to multiple of 16 bytes (CFB can work with partial blocks, but we keep it simple)
    if len(pt_bytes) % 16 != 0:
        pt_bytes += [0] * (16 - len(pt_bytes) % 16)
    # Encrypt
    ciphertext = aes_cfb_encrypt(pt_bytes, key_bytes, iv_bytes)
    print("Ciphertext (hex):", ''.join(f'{b:02x}' for b in ciphertext))
    # Decrypt
    recovered = aes_cfb_decrypt(ciphertext, key_bytes, iv_bytes)
    # Remove padding
    recovered_str = bytes_to_str(recovered[:len(plaintext)])
    print("Recovered Plaintext:", recovered_str)
    # Verify
    if recovered_str == plaintext:
        print("Success: Plaintext recovered correctly!")
    else:
        print("Error: Plaintext does not match!")
