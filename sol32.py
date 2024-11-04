#!/usr/bin/env python3
from Crypto.Util.strxor import strxor
import binascii

def create_forged_file():
    # Known IV from the code
    IV = b'fedcba9876543210'
    
    # Read original file content
    with open('fst.bin', 'rb') as f:
        original = f.read()
    
    # Read known MAC
    with open('mac1.txt', 'r') as f:
        known_mac = binascii.unhexlify(f.read().strip())
    
    # Create extended message
    # First part: original message (5 blocks)
    new_message = original
    
    # Add block that XORs with MAC
    # XOR of first block with IV 
    first_block = original[:16]
    xor_block = strxor(strxor(first_block, IV), known_mac)
    
    # Construct final message
    new_message = new_message + xor_block + original[16:64]  # Add middle blocks
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(new_message)
    
    return binascii.hexlify(known_mac).decode()

def main():
    mac = create_forged_file()
    print(f"Created snd.bin with MAC: {mac}")
    print(f"\nRun verification with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()