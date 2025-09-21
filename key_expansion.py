"""
key_expansion.py
Implements AES key expansion for 128-bit keys, with RotWord, SubWord, Rcon, and key schedule logic.
"""
from sbox import sub_word

# AES parameters for 128-bit key
Nk = 4  # Number of 32-bit words in key
Nb = 4  # Number of columns (block size in words)
Nr = 10 # Number of rounds

# Round constants (Rcon)
def rcon_gen():
    """
    Generates Rcon array for AES key expansion.
    Each Rcon[i] is [RCi, 0x00, 0x00, 0x00], RCi = 2^(i-1) in GF(2^8)
    """
    rcon = [[0x00, 0x00, 0x00, 0x00]]
    rc = 1
    for i in range(1, 11):
        rcon.append([rc, 0x00, 0x00, 0x00])
        # Multiply rc by 2 in GF(2^8)
        rc = rc << 1
        if rc & 0x100:
            rc ^= 0x11b
    return rcon

Rcon = rcon_gen()

def rot_word(word):
    """
    RotWord: Circular left shift of a word by 1 byte.
    [a0, a1, a2, a3] -> [a1, a2, a3, a0]
    """
    return word[1:] + word[:1]

# Key expansion function
def key_expansion(key_bytes):
    """
    Expands 128-bit key into 44 words (4 bytes each) for AES-128.
    key_bytes: list of 16 bytes
    Returns: list of 44 words (each word is 4 bytes)
    """
    w = []
    # Step 1: Copy original key
    for i in range(Nk):
        w.append(key_bytes[4*i:4*i+4])
    # Step 2: Expand key
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1].copy()
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            # XOR with round constant
            temp = [t ^ r for t, r in zip(temp, Rcon[i//Nk])]
        w.append([wi ^ ti for wi, ti in zip(w[i-Nk], temp)])
    return w

# Example usage (for testing):
if __name__ == "__main__":
    # Example 128-bit key (hex string)
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]
    expanded = key_expansion(key_bytes)
    print("Expanded Key Schedule:")
    for i, word in enumerate(expanded):
        print(f"w[{i}]:", [hex(b) for b in word])
