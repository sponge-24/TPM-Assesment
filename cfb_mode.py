"""
cfb_mode.py
Implements AES-128 CFB mode encryption and decryption using AES block functions.
"""
from aes_core import add_round_key, shift_rows, mix_columns, sub_bytes
from key_expansion import key_expansion, Nb, Nr

# Helper: Convert 16-byte array to 4x4 matrix
def bytes_to_matrix(b):
    """
    Converts a 16-byte array to a 4x4 matrix (column-major).
    """
    return [[b[4*c + r] for c in range(4)] for r in range(4)]

# Helper: Convert 4x4 matrix to 16-byte array
def matrix_to_bytes(m):
    """
    Converts a 4x4 matrix to a 16-byte array (column-major).
    """
    return [m[r][c] for c in range(4) for r in range(4)]

# AES block encryption (single block, no padding)
def aes_encrypt_block(plaintext, round_keys):
    """
    Encrypts a single 16-byte block using AES-128.
    plaintext: 16-byte array
    round_keys: list of 44 words (from key_expansion)
    Returns: 16-byte array (ciphertext)
    """
    state = bytes_to_matrix(plaintext)
    # Initial round
    state = add_round_key(state, bytes_to_matrix(sum(round_keys[0:4], [])))
    # 9 main rounds
    for rnd in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, bytes_to_matrix(sum(round_keys[4*rnd:4*(rnd+1)], [])))
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, bytes_to_matrix(sum(round_keys[4*Nr:4*(Nr+1)], [])))
    return matrix_to_bytes(state)

# CFB mode encryption
def     aes_cfb_encrypt(plaintext, key_bytes, iv):
    """
    Encrypts plaintext using AES-128 in CFB mode.
    plaintext: byte array
    key_bytes: 16-byte array
    iv: 16-byte array (initialization vector)
    Returns: ciphertext byte array
    """
    round_keys = key_expansion(key_bytes)
    block_size = 16
    ciphertext = []
    prev = iv.copy()
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        # Encrypt previous ciphertext (or IV for first block)
        enc = aes_encrypt_block(prev, round_keys)
        # XOR with plaintext block
        cipher_block = [b ^ e for b, e in zip(block, enc[:len(block)])]
        ciphertext.extend(cipher_block)
        prev = cipher_block.copy()
    return ciphertext

# CFB mode decryption
def aes_cfb_decrypt(ciphertext, key_bytes, iv):
    """
    Decrypts ciphertext using AES-128 in CFB mode.
    ciphertext: byte array
    key_bytes: 16-byte array
    iv: 16-byte array
    Returns: plaintext byte array
    """
    round_keys = key_expansion(key_bytes)
    block_size = 16
    plaintext = []
    prev = iv.copy()
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        enc = aes_encrypt_block(prev, round_keys)
        plain_block = [b ^ e for b, e in zip(block, enc[:len(block)])]
        plaintext.extend(plain_block)
        prev = block.copy()
    return plaintext
