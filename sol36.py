#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
import binascii

def create_forged_file():
    # Constants
    IV = b'fedcba9876543210'
    BLOCK_SIZE = 16
    
    # Read original file
    with open('fst.bin', 'rb') as f:
        original = f.read()  # 86 bytes
    
    # Read MAC
    with open('mac1.txt', 'r') as f:
        known_mac = f.read().strip()
    mac_bytes = binascii.unhexlify(known_mac)
    
    # Calculate initial padding
    padded_original = pad(original, BLOCK_SIZE)  # 96 bytes (6 blocks)
    
    # Following the sample approach for 10 blocks total:
    # 1. Take first 5 blocks (80 bytes)
    first_five_blocks = padded_original[:5*BLOCK_SIZE]
    
    # 2. Sixth block is the properly padded block
    sixth_block = padded_original[5*BLOCK_SIZE:6*BLOCK_SIZE]
    
    # 3. Create XOR block (7th block)
    # XOR of (first block XOR IV XOR MAC)
    first_block = padded_original[:BLOCK_SIZE]
    xor_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # 4. Add blocks 2-5 again (blocks 8-10)
    forged_msg = (
        first_five_blocks +     # Blocks 1-5 (original)
        sixth_block +          # Block 6 (padding)
        xor_block +            # Block 7 (XOR block)
        padded_original[BLOCK_SIZE:5*BLOCK_SIZE]  # Blocks 8-10 (duplicate of 2-5)
    )
    
    # Print length for verification
    print(f"Original length: {len(original)} bytes")
    print(f"Padded length: {len(padded_original)} bytes")
    print(f"Forged message length: {len(forged_msg)} bytes")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_msg)
    
    return known_mac

def main():
    mac = create_forged_file()
    print("\nMAC to use:", mac)
    print("\nRun verification with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()