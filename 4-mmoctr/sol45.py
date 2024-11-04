#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import *

H0 = b'0123456789abcdef'

def mmoctr(data):
    data = pad(data, AES.block_size)
    k = len(data)//AES.block_size 
    Hi = H0 
    for i in range(0,k): 
        x = data[i*16:(i+1)*16]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    return Hi

# Read original file
with open('fst.bin', 'rb') as f:
    fst_data = f.read()

# Get the hash of original file to match
target_hash = mmoctr(fst_data)

# Create a different file
snd_data = bytearray(48)  # Same length as original

# Process first block
Hi = H0
cipher = AES.new(Hi, AES.MODE_ECB)
x1 = strxor(target_hash, long_to_bytes(3, AES.block_size))  # Work backwards from target hash

# For the last block, we need something that will encrypt to x1
cipher = AES.new(Hi, AES.MODE_ECB)
last_block = cipher.decrypt(x1)  # This gives us what we need for last block

# Fill in our snd_data
snd_data[32:48] = last_block  # Put our crafted block at the end
snd_data[0:32] = fst_data[0:32]  # Keep first two blocks the same

with open('snd.bin', 'wb') as f:
    f.write(bytes(snd_data))

# Verify
print("Original hash:", mmoctr(fst_data).hex())
print("New hash:", mmoctr(bytes(snd_data)).hex())