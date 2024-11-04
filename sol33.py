#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
import binascii

def create_forged_file():
    # Read original file content
    with open('fst.bin', 'rb') as f:
        original = f.read()
    
    # Read known MAC
    with open('mac1.txt', 'r') as f:
        known_mac = f.read().strip()
        
    # Convert MAC from hex to bytes
    mac_bytes = binascii.unhexlify(known_mac)
    
    # Create a message that's one block shorter than original
    new_msg = original[:48]  # Take first 3 blocks
    
    # Add padding to ensure same block alignment
    padded_msg = pad(new_msg, AES.block_size)
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(padded_msg)
    
    return known_mac

def main():
    mac = create_forged_file()
    print(f"Created snd.bin with MAC: {mac}")
    print(f"\nRun verification with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()