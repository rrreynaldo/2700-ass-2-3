#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii

def create_forged_file():
    BLOCK_SIZE = 16
    IV = b'fedcba9876543210'
    
    # Read original file and MAC
    with open('fst.bin', 'rb') as f:
        original = f.read()
    with open('mac1.txt', 'r') as f:
        known_mac = f.read().strip()
    mac_bytes = binascii.unhexlify(known_mac)
    
    # Create blocks
    forged_msg = bytearray()
    
    # Take first 32 bytes (2 blocks) from original
    forged_msg.extend(original[:32])
    
    # Add XOR block using IV and MAC
    first_block = original[:BLOCK_SIZE]
    second_block = original[BLOCK_SIZE:2*BLOCK_SIZE]
    
    # Calculate XOR block that will help produce our target MAC
    xor_block = strxor(strxor(first_block, IV), mac_bytes)
    forged_msg.extend(xor_block)
    
    # Add the second block again
    forged_msg.extend(second_block)
    
    # Add padding to match block size
    padding_length = BLOCK_SIZE - (len(forged_msg) % BLOCK_SIZE)
    if padding_length < BLOCK_SIZE:
        forged_msg.extend(bytes([padding_length] * padding_length))
    
    print(f"Original length: {len(original)}")
    print(f"Forged length: {len(forged_msg)}")
    print("\nBlocks:")
    for i in range(0, len(forged_msg), BLOCK_SIZE):
        print(f"Block {i//BLOCK_SIZE + 1}: {' '.join(f'{b:02x}' for b in forged_msg[i:i+BLOCK_SIZE])}")
        
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_msg)
    
    return known_mac

def main():
    mac = create_forged_file()
    print(f"\nRun this command:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()