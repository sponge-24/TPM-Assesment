"""
aes_core.py
Implements AES block operations: AddRoundKey, ShiftRows, MixColumns, and their inverses.
"""
from sbox import sub_bytes, inv_sub_bytes

# AddRoundKey: XOR state with round key
def add_round_key(state, round_key):
    """
    XORs each byte of the state with the round key.
    state: 4x4 matrix
    round_key: 4x4 matrix
    Returns new state matrix.
    """
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

# ShiftRows operation
def shift_rows(state):
    """
    Cyclically shifts each row by its index.
    Row 0: no shift, Row 1: shift left by 1, etc.
    """
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3]
    ]

def inv_shift_rows(state):
    """
    Inverse of ShiftRows: shift right by row index.
    """
    return [
        state[0],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3]
    ]

# MixColumns helpers (GF(2^8) multiplication)
def xtime(a):
    """
    Multiplies by x (i.e., 2) in GF(2^8).
    """
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1)

def mix_single_column(col):
    """
    Mixes one column for MixColumns.
    """
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)
    return col

def mix_columns(state):
    """
    MixColumns transformation: mixes each column using GF(2^8) arithmetic.
    """
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]
    return state

# Inverse MixColumns
def inv_mix_single_column(col):
    """
    Inverse MixColumns for one column.
    """
    # Multiply by fixed matrix in GF(2^8)
    def mul(a, b):
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xff
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p
    return [
        mul(col[0], 0x0e) ^ mul(col[1], 0x0b) ^ mul(col[2], 0x0d) ^ mul(col[3], 0x09),
        mul(col[0], 0x09) ^ mul(col[1], 0x0e) ^ mul(col[2], 0x0b) ^ mul(col[3], 0x0d),
        mul(col[0], 0x0d) ^ mul(col[1], 0x09) ^ mul(col[2], 0x0e) ^ mul(col[3], 0x0b),
        mul(col[0], 0x0b) ^ mul(col[1], 0x0d) ^ mul(col[2], 0x09) ^ mul(col[3], 0x0e)
    ]

def inv_mix_columns(state):
    """
    Inverse MixColumns transformation.
    """
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]
    return state
