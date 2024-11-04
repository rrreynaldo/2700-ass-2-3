#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
import binascii

def create_forged_file():
    # Read original file
    with open('fst.bin', 'rb') as f:
        original = f.read()
    
    # Known IV from the code
    IV = b'fedcba9876543210'
    
    # Read known MAC
    with open('mac1.txt', 'r') as f:
        known_mac = f.read().strip()
    mac_bytes = binascii.unhexlify(known_mac)
    
    # Calculate blocks needed
    block_size = AES.block_size  # 16 bytes
    
    # Create new message
    # Start with original message
    msg = original
    
    # Add a block that will help cancel out previous blocks
    cancel_block = strxor(mac_bytes, IV)
    
    # Create the forged message
    forged_msg = msg + cancel_block
    
    # Add additional block to maintain proper padding
    padding_needed = block_size - (len(forged_msg) % block_size)
    forged_msg = forged_msg + bytes([padding_needed] * padding_needed)
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(forged_msg)
    
    return known_mac

def main():
    mac = create_forged_file()
    print(f"Created snd.bin with MAC: {mac}")
    print(f"\nRun verification with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()