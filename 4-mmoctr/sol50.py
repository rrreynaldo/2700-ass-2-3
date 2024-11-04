from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
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
    
    # Create a different first block but keep remaining blocks the same
    # Simply XOR the first block with counter 1 twice to make it different
    # but produce the same result after hash calculation
    new_blocks = blocks[:]
    new_blocks[0] = strxor(strxor(blocks[0], long_to_bytes(1, AES.block_size)), 
                          long_to_bytes(1, AES.block_size))
    
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