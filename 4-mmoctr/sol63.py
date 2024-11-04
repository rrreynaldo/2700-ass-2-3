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
    # Calculate the padding
    padding_length = 16 - (len(original_data) % 16)
    padding_byte = bytes([padding_length]) * padding_length
    
    # Get original chain without padding
    Hi = H0
    blocks = [original_data[i:i+16] for i in range(0, len(original_data), 16)]
    
    print("\nOriginal blocks (before padding):")
    for i, block in enumerate(blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    # Process the original chain
    hash_chain = [Hi]
    for i, block in enumerate(blocks):
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(block), long_to_bytes(i+1, AES.block_size))
        hash_chain.append(Hi)
        print(f"H{i+1}: {Hi.hex()}")
    
    # Add padding block
    cipher = AES.new(Hi, AES.MODE_ECB)
    Hi = strxor(cipher.encrypt(padding_byte), long_to_bytes(len(blocks)+1, AES.block_size))
    hash_chain.append(Hi)
    print(f"Final hash after padding: {Hi.hex()}")
    
    # Now try to find a modified third block
    modified_data = bytearray(original_data)
    block_to_modify = 2  # Modify third block (index 2)
    
    # Try systematic modifications of the third block
    original_block = blocks[block_to_modify]
    prev_hash = hash_chain[block_to_modify]
    target_hash = hash_chain[block_to_modify + 1]
    
    print(f"\nTrying to modify block {block_to_modify + 1}:")
    print(f"Previous hash: {prev_hash.hex()}")
    print(f"Target hash: {target_hash.hex()}")
    
    # Try flipping bits in the block
    for byte_pos in range(16):
        for bit_pos in range(8):
            modified_block = bytearray(original_block)
            modified_block[byte_pos] ^= (1 << bit_pos)
            
            cipher = AES.new(prev_hash, AES.MODE_ECB)
            test_hash = strxor(cipher.encrypt(bytes(modified_block)), 
                             long_to_bytes(block_to_modify + 1, AES.block_size))
            
            if test_hash == target_hash and bytes(modified_block) != original_block:
                print(f"\nFound collision at byte {byte_pos}, bit {bit_pos}!")
                modified_data[block_to_modify*16:(block_to_modify+1)*16] = modified_block
                return bytes(modified_data)
    
    return None

def verify_collision(original_data, new_data):
    if new_data is None:
        return False
        
    print("\nVerifying collision:")
    print(f"Original length: {len(original_data)}")
    print(f"New length: {len(new_data)}")
    
    orig_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    print(f"\nOriginal Data: {original_data.hex()}")
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