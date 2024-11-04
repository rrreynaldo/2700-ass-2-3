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
    # First, let's understand the state after processing the original file
    fst_padded = pad(fst_data, AES.block_size)
    blocks = len(fst_padded)//AES.block_size
    
    # Get the original hash
    original_hash = mmoctr(fst_data)
    
    # Create a new file that's one block longer
    snd_data = bytearray(fst_data)
    
    # Add an extra block of data
    # We'll try to manipulate this block to get the same hash
    extra_block = bytearray(16)  # Start with zeros
    
    # Try different values for the extra block
    Hi = H0
    for i in range(blocks):
        x = fst_padded[i*16:(i+1)*16]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    
    # Now Hi contains the state before our extra block
    # We need to find an extra block that, when processed, gives us the same final hash
    cipher = AES.new(Hi, AES.MODE_ECB)
    
    # Calculate what encryption of our block should be to get original hash
    target = strxor(original_hash, long_to_bytes(blocks+1, AES.block_size))
    
    # Append the extra block
    snd_data.extend(extra_block)
    
    return pad(bytes(snd_data), AES.block_size)

# Read original file
with open('fst.bin', 'rb') as f:
    fst_bytes = f.read()

print(f"Original file size: {len(fst_bytes)} bytes")
print(f"Original file content (hex): {fst_bytes.hex()}")

# Generate collision
snd_bytes = find_collision(fst_bytes)

# Save to file
with open("snd.bin", "wb") as f:
    f.write(snd_bytes)

print("\nSecond pre-image has been written to snd.bin")
print(f"New file size: {len(snd_bytes)} bytes")
print(f"New file content (hex): {snd_bytes.hex()}")

# Verify hashes
orig_hash = mmoctr(fst_bytes)
new_hash = mmoctr(snd_bytes)
print("\nVerifying hashes:")
print(f"Original file hash: {orig_hash.hex()}")
print(f"New file hash: {new_hash.hex()}")

# Verify they match
if orig_hash == new_hash:
    print("Success! Hashes match.")
else:
    print("Error: Hashes don't match.")