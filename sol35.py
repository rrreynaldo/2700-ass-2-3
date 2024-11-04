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
    
    # Step 1: Create initial blocks (5 complete blocks + partial 6th block)
    padded_original = pad(original, BLOCK_SIZE)  # Will be 96 bytes (6 blocks)
    
    # Step 2: Create extension block
    # This block will be XORed with the MAC and IV
    first_block = original[:BLOCK_SIZE]
    extension_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # Step 3: Construct new message
    # Take original 5 blocks and add our extension
    new_msg = padded_original + extension_block
    
    # Step 4: Add blocks 2-6 again (cycling)
    new_msg = new_msg + padded_original[BLOCK_SIZE:]
    
    # Step 5: Ensure proper padding for final block
    final_padding = BLOCK_SIZE - (len(new_msg) % BLOCK_SIZE)
    if final_padding < BLOCK_SIZE:
        new_msg = new_msg + bytes([final_padding] * final_padding)
    
    # Write forged message
    with open('snd.bin', 'wb') as f:
        f.write(new_msg)
    
    return known_mac

def main():
    mac = create_forged_file()
    print("Attack explanation:")
    print("1. Original file is 86 bytes -> padded to 96 bytes (6 blocks)")
    print("2. Created extension using MAC and IV")
    print("3. Cycled blocks to create a different message with same MAC")
    print(f"\nMAC to use: {mac}")
    print(f"\nRun verification with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()