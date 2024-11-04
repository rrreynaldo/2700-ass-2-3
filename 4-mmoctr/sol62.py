from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
import os

H0 = b'0123456789abcdef'

def mmoctr(data):
    data = pad(data, AES.block_size)
    k = len(data)//AES.block_size
    Hi = H0
    for i in range(k):
        x = data[i*16:(i+1)*16]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    return Hi

def find_second_preimage(original_data):
    # Extract the original blocks
    padded = pad(original_data, AES.block_size)
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    
    # Get original hash chain
    Hi = H0
    hash_chain = [Hi]
    for i, block in enumerate(blocks):
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(block), long_to_bytes(i+1, AES.block_size))
        hash_chain.append(Hi)
    
    # Create new blocks
    new_blocks = []
    Hi = H0
    
    # For each block, try to find a different block that leads to the same next hash
    for i, orig_block in enumerate(blocks):
        found = False
        cipher = AES.new(Hi, AES.MODE_ECB)
        target_hash = hash_chain[i+1]
        
        # Try random blocks until we find one that works
        attempts = 0
        while not found and attempts < 1000:
            # Generate a random block
            test_block = os.urandom(16)
            if test_block == orig_block:
                continue
                
            # Calculate its hash
            encrypted = cipher.encrypt(test_block)
            test_hash = strxor(encrypted, long_to_bytes(i+1, AES.block_size))
            
            if test_hash == target_hash:
                found = True
                new_blocks.append(test_block)
                Hi = test_hash
            attempts += 1
            
        if not found:
            new_blocks.append(orig_block)
            Hi = target_hash
            
    return b''.join(new_blocks)

def verify_collision(original_data, new_data):
    print("\nVerifying collision:")
    orig_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    print(f"Original Data: {original_data.hex()}")
    print(f"New Data:      {new_data.hex()}")
    print(f"Original Hash: {orig_hash.hex()}")
    print(f"New Hash:      {new_hash.hex()}")
    print(f"Target Hash:   e758f7ce30186a937f073fd4ddab8393")
    
    return orig_hash == new_hash and original_data != new_data

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = find_second_preimage(original_data)
    
    if verify_collision(original_data, new_data):
        print("\nFound valid second preimage!")
        with open('snd.bin', 'wb') as f:
            f.write(new_data)
    else:
        print("\nNo valid collision found")

if __name__ == "__main__":
    main()