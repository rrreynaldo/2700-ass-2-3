#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import *

# Constants
H0 = b'0123456789abcdef'

def get_second_block_hash(fst_data):
    data = pad(fst_data, AES.block_size)
    Hi = H0
    
    # Process first block
    x = data[0:16]
    cipher = AES.new(Hi, AES.MODE_ECB)
    Hi = strxor(cipher.encrypt(x), long_to_bytes(1, AES.block_size))
    
    # Process second block
    x = data[16:32]
    cipher = AES.new(Hi, AES.MODE_ECB)
    Hi = strxor(cipher.encrypt(x), long_to_bytes(2, AES.block_size))
    
    return Hi

# Read original file
with open('fst.bin', 'rb') as f:
    fst_data = f.read()

# Create first block of zeros
arb = b'0' * 16

# Get second block hash
H0 = b'0123456789abcdef'
cipher = AES.new(H0, AES.MODE_ECB)
H1 = strxor(cipher.encrypt(arb), long_to_bytes(1, AES.block_size))

# Create second block using hash of second block from original file
second_block_hash = get_second_block_hash(fst_data)
cipher = AES.new(H1, AES.MODE_ECB)
second_block = cipher.decrypt(second_block_hash)  # Decrypt to get required block

# Construct final preimage
snd_data = arb + second_block + fst_data[32:48]

# Write to file
with open('snd.bin', 'wb') as f:
    f.write(snd_data)

print("Second pre-image has been written to snd.bin")
print("Original length:", len(fst_data))
print("New length:", len(snd_data))