from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import sys

H0 = b'0123456789abcdef'

def read_file_bytes(filename):
    with open(filename, 'rb') as f:
        return f.read()

def create_second_preimage(original_data):
    # Pad the original data
    padded_data = pad(original_data, AES.block_size)
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    
    # Calculate the hash of the original data to get final H_n
    k = len(padded_data) // AES.block_size
    Hi = H0
    for i in range(k):
        x = blocks[i]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    
    final_hash = Hi
    
    # Create a new first block that will lead to the same final hash
    # We'll keep the same second block onwards
    new_blocks = blocks[:]
    
    # Calculate what encryption of our new first block should produce
    target = strxor(blocks[0], long_to_bytes(1, AES.block_size))
    
    # Create a different first block that encrypts to the same value
    cipher = AES.new(H0, AES.MODE_ECB)
    new_blocks[0] = strxor(blocks[0], long_to_bytes(1, AES.block_size))
    
    # Combine blocks back into a file
    new_data = b''.join(new_blocks)
    
    return new_data

def main():
    # Read original file
    original_data = read_file_bytes('fst.bin')
    
    # Create second preimage
    new_data = create_second_preimage(original_data)
    
    # Write to new file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("Second preimage has been written to snd.bin")

if __name__ == "__main__":
    main()