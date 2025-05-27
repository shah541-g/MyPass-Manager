from tkinter import *
from tkinter import messagebox
import random
import pyperclip
import json
import os
import base64
import sys

def resource_path(relative_path):
    """Get the absolute path to a resource, works for dev and PyInstaller."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Global variables
current_user = None
web_entry = None
email_entry = None
password_entry = None
master_password_hash = None

# ---------------------------- MANUAL SHA-256 IMPLEMENTATION ------------------------------- #
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def rotr(x, n):
    """Right rotate x by n bits."""
    return (x >> n) | (x << (32 - n)) & 0xffffffff

def sha256_manual(message):
    """Manual SHA-256 hashing of a string message."""
    msg_bytes = message.encode('utf-8')
    msg_len = len(msg_bytes) * 8

    padding = b'\x80' + b'\x00' * ((56 - (len(msg_bytes) + 1) % 64) % 64)
    msg_len_bytes = (msg_len).to_bytes(8, byteorder='big')
    padded_msg = msg_bytes + padding + msg_len_bytes

    h = H.copy()

    for i in range(0, len(padded_msg), 64):
        chunk = padded_msg[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], byteorder='big')
        for j in range(16, 64):
            s0 = rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, hh = h

        for j in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + S1 + ch + K[j] + w[j]) & 0xffffffff
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            hh = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + hh) & 0xffffffff

    hash_result = ''.join(f'{x:08x}' for x in h)
    return hash_result

# ---------------------------- MANUAL AES-GCM IMPLEMENTATION ------------------------------- #
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def sub_bytes(state):
    return [SBOX[b] for b in state]

def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def shift_rows(state):
    s = [state[i*4+j] for i in range(4) for j in range(4)]
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s

def inv_shift_rows(state):
    s = [state[i*4+j] for i in range(4) for j in range(4)]
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[14], s[2], s[6], s[10]
    s[3], s[7], s[11], s[15] = s[11], s[15], s[3], s[7]
    return s

def mix_columns(state):
    def gf_mult(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b
            a &= 0xff
            b >>= 1
        return p & 0xff

    s = [0] * 16
    for c in range(4):
        s[c] = gf_mult(0x02, state[c]) ^ gf_mult(0x03, state[c+4]) ^ state[c+8] ^ state[c+12]
        s[c+4] = state[c] ^ gf_mult(0x02, state[c+4]) ^ gf_mult(0x03, state[c+8]) ^ state[c+12]
        s[c+8] = state[c] ^ state[c+4] ^ gf_mult(0x02, state[c+8]) ^ gf_mult(0x03, state[c+12])
        s[c+12] = gf_mult(0x03, state[c]) ^ state[c+4] ^ state[c+8] ^ gf_mult(0x02, state[c+12])
    return s

def inv_mix_columns(state):
    def gf_mult(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b
            a &= 0xff
            b >>= 1
        return p & 0xff

    s = [0] * 16
    for c in range(4):
        s[c] = gf_mult(0x0e, state[c]) ^ gf_mult(0x0b, state[c+4]) ^ gf_mult(0x0d, state[c+8]) ^ gf_mult(0x09, state[c+12])
        s[c+4] = gf_mult(0x09, state[c]) ^ gf_mult(0x0e, state[c+4]) ^ gf_mult(0x0b, state[c+8]) ^ gf_mult(0x0d, state[c+12])
        s[c+8] = gf_mult(0x0d, state[c]) ^ gf_mult(0x09, state[c+4]) ^ gf_mult(0x0e, state[c+8]) ^ gf_mult(0x0b, state[c+12])
        s[c+12] = gf_mult(0x0b, state[c]) ^ gf_mult(0x0d, state[c+4]) ^ gf_mult(0x09, state[c+8]) ^ gf_mult(0x0e, state[c+12])
    return s

def add_round_key(state, key):
    return [state[i] ^ key[i] for i in range(16)]

def key_expansion(key):
    w = [0] * 60
    for i in range(8):
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
    
    for i in range(8, 60):
        temp = w[i-1]
        if i % 8 == 0:
            temp = (SBOX[(temp >> 16) & 0xff] << 24) | (SBOX[(temp >> 8) & 0xff] << 16) | (SBOX[temp & 0xff] << 8) | SBOX[(temp >> 24) & 0xff]
            temp ^= RCON[(i // 8) - 1] << 24
        elif i % 8 == 4:
            temp = (SBOX[(temp >> 24) & 0xff] << 24) | (SBOX[(temp >> 16) & 0xff] << 16) | (SBOX[(temp >> 8) & 0xff] << 8) | SBOX[temp & 0xff]
        w[i] = w[i-8] ^ temp
    
    round_keys = []
    for i in range(0, 60, 4):
        key = []
        for j in range(4):
            for k in range(4):
                key.append((w[i+j] >> (24 - k*8)) & 0xff)
        round_keys.append(key)
    return round_keys

def aes_encrypt_block(block, round_keys):
    state = [b for b in block]
    state = add_round_key(state, round_keys[0])
    
    for round in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round])
    
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[14])
    
    return state

def aes_decrypt_block(block, round_keys):
    state = [b for b in block]
    state = add_round_key(state, round_keys[14])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    for round in range(13, 0, -1):
        state = add_round_key(state, round_keys[round])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    
    state = add_round_key(state, round_keys[0])
    return state

def inc_counter(counter):
    for i in range(len(counter) - 1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xff
        if counter[i] != 0:
            break
    return counter

def aes_ctr_encrypt(plaintext, key, nonce):
    round_keys = key_expansion(key)
    ciphertext = []
    counter = [0] * 4 + list(nonce) + [0] * 4
    
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        keystream = aes_encrypt_block(counter, round_keys)
        for j in range(len(block)):
            ciphertext.append(block[j] ^ keystream[j])
        counter = inc_counter(counter)
    
    return bytes(ciphertext)

def aes_ctr_decrypt(ciphertext, key, nonce):
    return aes_ctr_encrypt(ciphertext, key, nonce)  # CTR mode is symmetric

def gf_mult_128(a, b):
    p = 0
    for _ in range(128):
        if b & 1:
            p ^= a
        hi_bit_set = a & (1 << 127)
        a <<= 1
        if hi_bit_set:
            a ^= 0x87
        a &= (1 << 128) - 1
        b >>= 1
    return p

def ghash(h, data):
    x = 0
    block_size = 16
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        block_int = int.from_bytes(block.ljust(16, b'\x00'), 'big')
        x ^= block_int
        x = gf_mult_128(x, h)
    return x.to_bytes(16, 'big')

def encrypt_password(password, master_password_hash):
    """Encrypt the password using manual AES-GCM with the master password hash as the key."""
    key = hash_to_bytes(master_password_hash)
    if key is None:
        print("Encryption failed: Invalid master password hash")
        return None
    
    nonce = os.urandom(12)
    plaintext = password.encode('utf-8')
    
    # AES-CTR encryption
    ciphertext = aes_ctr_encrypt(plaintext, key, nonce)
    
    # Compute GHASH for authentication
    round_keys = key_expansion(key)
    h = aes_encrypt_block([0] * 16, round_keys)
    h_int = int.from_bytes(bytes(h), 'big')
    
    aad = b''  # No additional authenticated data
    len_aad = (len(aad) * 8).to_bytes(8, 'big')
    len_c = (len(ciphertext) * 8).to_bytes(8, 'big')
    ghash_input = aad + ciphertext + len_aad + len_c
    tag = ghash(h_int, ghash_input)
    
    # Encrypt tag with initial counter block
    counter = [0] * 4 + list(nonce) + [0] * 4
    keystream = aes_encrypt_block(counter, round_keys)
    tag = bytes(t1 ^ t2 for t1, t2 in zip(tag, keystream[:16]))
    
    return {
        "encrypted_password": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }

def decrypt_password(encrypted_data, master_password_hash):
    """Decrypt the password using manual AES-GCM with the master password hash as the key."""
    try:
        if not isinstance(encrypted_data, dict) or \
           "encrypted_password" not in encrypted_data or \
           "nonce" not in encrypted_data or \
           "tag" not in encrypted_data:
            print("Decryption failed: Invalid encrypted data format (missing fields)")
            return None
        
        try:
            ciphertext = base64.b64decode(encrypted_data["encrypted_password"])
            nonce = base64.b64decode(encrypted_data["nonce"])
            tag = base64.b64decode(encrypted_data["tag"])
        except base64.binascii.Error as e:
            print(f"Decryption failed: Base64 decoding error - {e}")
            return None

        key = hash_to_bytes(master_password_hash)
        if key is None:
            print("Decryption failed: Invalid master password hash")
            return None

        # Verify tag
        round_keys = key_expansion(key)
        h = aes_encrypt_block([0] * 16, round_keys)
        h_int = int.from_bytes(bytes(h), 'big')
        
        aad = b''
        len_aad = (len(aad) * 8).to_bytes(8, 'big')
        len_c = (len(ciphertext) * 8).to_bytes(8, 'big')
        ghash_input = aad + ciphertext + len_aad + len_c
        computed_tag = ghash(h_int, ghash_input)
        
        counter = [0] * 4 + list(nonce) + [0] * 4
        keystream = aes_encrypt_block(counter, round_keys)
        computed_tag = bytes(t1 ^ t2 for t1, t2 in zip(computed_tag, keystream[:16]))
        
        if computed_tag != tag:
            print("Decryption failed: Authentication tag mismatch (wrong key or tampered data)")
            return None

        # AES-CTR decryption
        plaintext = aes_ctr_decrypt(ciphertext, key, nonce)
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: Unexpected error - {e}")
        return None

def hash_to_bytes(hash_str):
    """Convert a SHA-256 hash string (64 hex chars) to 32 bytes."""
    try:
        return bytes.fromhex(hash_str)
    except ValueError as e:
        print(f"Error converting hash to bytes: {e}")
        return None

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def gen_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_list = [random.choice(letters) for _ in range(nr_letters)]
    password_list += [random.choice(symbols) for _ in range(nr_symbols)]
    password_list += [random.choice(numbers) for _ in range(nr_numbers)]
    
    random.shuffle(password_list)
    password = "".join(password_list)
    
    password_entry.delete(0, END)
    password_entry.insert(0, password)
    pyperclip.copy(password)

# ---------------------------- SAVE PASSWORD ------------------------------- #
def save_password():
    global current_user, master_password_hash
    website = web_entry.get()
    email = current_user
    password = password_entry.get()
    
    if not website or not password:
        messagebox.showinfo(title="Info", message="Incomplete Information")
        return
    
    if master_password_hash is None:
        messagebox.showerror(title="Error", message="No master password hash available. Please log in again.")
        return
    
    encrypted_data = encrypt_password(password, master_password_hash)
    if encrypted_data is None:
        messagebox.showerror(title="Error", message="Encryption failed. Please try again.")
        return
    
    new_password = {
        website: {
            "email": email,
            "encrypted_password": encrypted_data["encrypted_password"],
            "nonce": encrypted_data["nonce"],
            "tag": encrypted_data["tag"]
        }
    }
    
    json_file = f"{email.replace('@', '_').replace('.', '_')}_passwords.json"
    try:
        with open(json_file, mode="r") as file:
            data = json.load(file)
        if website in data:
            response = messagebox.askyesno(
                title="Website Exists",
                message=f"Credentials for {website} already exist. Do you want to update the password?"
            )
            if not response:
                return
        data.update(new_password)
        with open(json_file, mode="w") as file:
            json.dump(data, file, indent=4)
    except FileNotFoundError:
        with open(json_file, mode="w") as file:
            json.dump(new_password, file, indent=4)
    except json.JSONDecodeError:
        messagebox.showerror(title="Error", message="Corrupted JSON file. Starting fresh.")
        with open(json_file, mode="w") as file:
            json.dump(new_password, file, indent=4)
            
    finally:
        web_entry.delete(0, END)
        password_entry.delete(0, END)

# ---------------------------- SEARCH PASSWORD ------------------------------- #
def search_password():
    global current_user, master_password_hash
    website = web_entry.get()
    email = current_user
    
    if not website:
        messagebox.showinfo(title="Info", message="Please provide the website")
        return
    
    if master_password_hash is None:
        messagebox.showerror(title="Error", message="No master password hash available. Please log in again.")
        return
    
    json_file = f"{email.replace('@', '_').replace('.', '_')}_passwords.json"
    try:
        with open(json_file, mode="r") as file:
            data = json.load(file)
        
        if website in data:
            if data[website]["email"] == email:
                encrypted_data = {
                    "encrypted_password": data[website]["encrypted_password"],
                    "nonce": data[website]["nonce"],
                    "tag": data[website].get("tag")
                }
                if encrypted_data["tag"] is None:
                    messagebox.showerror(title="Error", message="Password data is in an old format. Please save a new password for this website.")
                    return
                decrypted_password = decrypt_password(encrypted_data, master_password_hash)
                if decrypted_password is None:
                    messagebox.showerror(title="Error", message="Failed to decrypt password. Data may be corrupted or incompatible. Please try saving a new password.")
                    return
                dialog = Toplevel()
                dialog.title(website)
                dialog_width = 300
                dialog_height = 150
                screen_width = dialog.winfo_screenwidth()
                screen_height = dialog.winfo_screenheight()
                x = (screen_width - dialog_width) // 2
                y = (screen_height - dialog_height) // 2
                dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
                Label(dialog, text=f"Email: {email}\nPassword: {decrypted_password}", pady=10).pack()
                Button(dialog, text="Copy Password", command=lambda: [pyperclip.copy(decrypted_password), dialog.destroy()], bg="green", fg="white").pack(pady=5)
                Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
                password_entry.delete(0, END)
                password_entry.insert(0, decrypted_password)
            else:
                messagebox.showerror(title="Error", message=f"No account found for {email} on {website}")
        else:
            messagebox.showinfo(title=website, message="No such website exists")
    except:
        messagebox.showinfo(title=website, message="No such website exists")

# ---------------------------- LOGIN PAGE ------------------------------- #
def show_main_app():
    login_window.destroy()
    setup_main_ui()

def login():
    global current_user, master_password_hash
    email = login_email_entry.get()
    password = login_password_entry.get()
    
    if not email or not password:
        messagebox.showinfo(title="Info", message="Please provide email and password")
        return
    
    try:
        with open("users.json", mode="r") as file:
            users = json.load(file)
    except:
        messagebox.showerror(title="Error", message="No users found. Please create an account.")
        return
    
    if email in users:
        hashed_password = sha256_manual(password)
        if users[email]["password"] == hashed_password:
            current_user = email
            master_password_hash = hashed_password
            show_main_app()
        else:
            messagebox.showerror(title="Error", message="Incorrect password")
    else:
        messagebox.showinfo(title="Info", message="No account found. Please create an account.")

def create_account():
    email = login_email_entry.get()
    password = login_password_entry.get()
    
    if not email or not password:
        messagebox.showinfo(title="Info", message="Please provide email and password")
        return
    
    hashed_password = sha256_manual(password)
    new_user = {
        email: {
            "password": hashed_password
        }
    }
    
    try:
        with open("users.json", mode="r") as file:
            users = json.load(file)
        if email in users:
            messagebox.showerror(title="Error", message="Account already exists")
        else:
            users.update(new_user)
            with open("users.json", mode="w") as file:
                json.dump(users, file, indent=4)
            messagebox.showinfo(title="Success", message="Account created! Please log in.")
            login_email_entry.delete(0, END)
            login_password_entry.delete(0, END)
    except:
        with open("users.json", mode="w") as file:
            json.dump(new_user, file, indent=4)
        messagebox.showinfo(title="Success", message="Account created! Please log in.")
        login_email_entry.delete(0, END)
        login_password_entry.delete(0, END)

# ---------------------------- LOGIN UI ------------------------------- #
login_window = Tk()
login_window.title("Login to Password Manager")
login_window.config(padx=20, pady=20, bg="light blue")

window_width = 400
window_height = 350
screen_width = login_window.winfo_screenwidth()
screen_height = login_window.winfo_screenheight()
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
login_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

canvas = Canvas(width=200, height=200, bg="light blue", highlightthickness=0)
img = PhotoImage(file=resource_path("logo.png"))
canvas.create_image(100, 100, image=img)

canvas.grid(column=0, row=0, columnspan=2)

Label(login_window, text="Email:", bg="light blue").grid(column=0, row=1, sticky="E")
login_email_entry = Entry(login_window, width=40)
login_email_entry.grid(column=1, row=1, pady=5)

Label(login_window, text="Master Password:", bg="light blue").grid(column=0, row=2, sticky="E")
login_password_entry = Entry(login_window, width=40, show="*")
login_password_entry.grid(column=1, row=2, pady=5)

Button(login_window, text="Login", bg="blue", fg="white", width=15, command=login).grid(column=1, row=3, pady=5)
Button(login_window, text="Create Account", bg="green", fg="white", width=15, command=create_account).grid(column=1, row=4, pady=5)

# ---------------------------- MAIN APP UI ------------------------------- #
def setup_main_ui():
    global web_entry, email_entry, password_entry
    
    window = Tk()
    window.title("Password Manager")
    window.config(padx=20, pady=20, bg="light blue")

    window_width = 450
    window_height = 400
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    canvas = Canvas(width=200, height=200, bg="light blue", highlightthickness=0)
    img = PhotoImage(file=resource_path("logo.png"))
    canvas.create_image(100, 100, image=img)
    canvas.grid(column=1, row=0)

    label_1 = Label(text="Website: ", bg="light blue")
    label_1.grid(column=0, row=1)

    label_2 = Label(text="Email/Username: ", bg="light blue", pady=10)
    label_2.grid(column=0, row=2)

    label_3 = Label(text="Password: ", pady=10, bg="light blue")
    label_3.grid(column=0, row=3)

    web_entry = Entry()
    web_entry.config(width=32)
    web_entry.grid(column=1, row=1)

    email_entry = Entry()
    email_entry.config(width=50, state="disabled", disabledbackground="#D3D3D3")
    email_entry.grid(column=1, row=2, columnspan=2)
    email_entry.config(state="normal")
    email_entry.insert(0, current_user)
    email_entry.config(state="disabled")

    password_entry = Entry()
    password_entry.config(width=32)
    password_entry.grid(column=1, row=3)

    gen_pass_btn = Button(text="Generate Password", bg="brown", fg="white", command=gen_password)
    gen_pass_btn.grid(column=2, row=3, padx=5)

    search_btn = Button(text="Search", bg="brown", fg="white", command=search_password, width=15)
    search_btn.grid(column=2, row=1)

    add_btn = Button(text="Add", width=42, bg="blue", fg="white", command=save_password)
    add_btn.grid(row=4, column=1, columnspan=2)

    window.mainloop()

login_window.mainloop()