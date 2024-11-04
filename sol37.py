#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
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
    
    # Calculate proper PKCS#7 padding
    padding_length = BLOCK_SIZE - (len(original) % BLOCK_SIZE)  # = 10
    padding_value = padding_length  # = 0x0A
    padding = bytes([padding_value] * padding_length)
    
    # Create padded original (86 bytes + 10 bytes of 0x0A)
    padded_original = original + padding
    
    print(f"Original length: {len(original)} bytes")
    print(f"Padding length: {padding_length} bytes")
    print(f"Padding value: 0x{padding_value:02x}")
    print(f"Padded length: {len(padded_original)} bytes")
    
    # Create forged message blocks
    # 1. First 5 blocks of original data (80 bytes)
    forged_msg = padded_original[:5*BLOCK_SIZE]
    
    # 2. Add the 6th block with proper padding
    forged_msg += padded_original[5*BLOCK_SIZE:6*BLOCK_SIZE]
    
    # 3. Add XOR block
    first_block = padded_original[:BLOCK_SIZE]
    xor_block = strxor(strxor(first_block, IV), mac_bytes)
    forged_msg += xor_block
    
    # 4. Add blocks 2-5 again
    forged_msg += padded_original[BLOCK_SIZE:5*BLOCK_SIZE]
    
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