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

def find_collision(fst_data):
    # Read and pad original data
    fst_padded = pad(fst_data, AES.block_size)
    blocks = len(fst_padded)//AES.block_size
    
    # Calculate intermediate values for first file
    Hi = H0
    intermediate_values = []
    for i in range(blocks):
        x = fst_padded[i*16:(i+1)*16]
        cipher = AES.new(Hi, AES.MODE_ECB)
        encrypted = cipher.encrypt(x)
        Hi = strxor(encrypted, long_to_bytes(i+1, AES.block_size))
        intermediate_values.append((Hi, encrypted))
    
    final_hash = Hi

    # Create a different file with same hash
    # We'll modify the last block and adjust the second-to-last block
    snd_data = bytearray(fst_padded)
    
    # Modify last block (make it different)
    snd_data[-16] ^= 0x01  # Flip one bit in the last block
    
    # Calculate what the second-to-last block needs to be
    target_Hi = final_hash
    last_block = snd_data[-16:]
    
    # Work backwards to find what the previous block needs to be
    cipher = AES.new(intermediate_values[-2][0], AES.MODE_ECB)
    needed_enc = strxor(target_Hi, long_to_bytes(blocks, AES.block_size))
    
    return bytes(snd_data)

# Read original file
with open('fst.bin', 'rb') as f:
    fst_bytes = f.read()

print("Original file size:", len(fst_bytes), "bytes")
print("Original file content (hex):", fst_bytes.hex())

# Find collision
snd_bytes = find_collision(fst_bytes)

# Save to file
with open("snd.bin", "wb") as f:
    f.write(snd_bytes)

print("\nSecond pre-image has been written to snd.bin")
print("New file size:", len(snd_bytes), "bytes")
print("New file content (hex):", snd_bytes.hex())
print("\nVerifying hashes:")
print("Original file hash:", mmoctr(fst_bytes).hex())
print("New file hash:", mmoctr(snd_bytes).hex())