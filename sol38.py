#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii

def print_hex_blocks(data):
    """Print data in hex format with block separation"""
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        print(f"Block {i//16 + 1}: {' '.join(f'{b:02x}' for b in block)}")

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
    
    # Create forged message (10 blocks total)
    forged_msg = bytearray()
    
    # Blocks 1-5: First 5 blocks of original
    forged_msg.extend(padded_original[:5*BLOCK_SIZE])
    
    # Block 6: Last block with padding
    forged_msg.extend(padded_original[5*BLOCK_SIZE:6*BLOCK_SIZE])
    
    # Block 7: XOR block
    first_block = padded_original[:BLOCK_SIZE]
    xor_block = strxor(strxor(first_block, IV), mac_bytes)
    forged_msg.extend(xor_block)
    
    # Blocks 8-10: Duplicate blocks 2-4
    forged_msg.extend(padded_original[BLOCK_SIZE:4*BLOCK_SIZE])
    
    print("\nForged message structure (10 blocks):")
    print_hex_blocks(forged_msg)
    
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