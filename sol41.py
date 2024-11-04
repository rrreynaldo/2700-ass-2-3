#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii

def create_forged_file():
    BLOCK_SIZE = 16
    IV = b'fedcba9876543210'
    MAC = "400b3f71959baf64ccfdb8f45d9246f3"
    mac_bytes = binascii.unhexlify(MAC)
    
    # Read original file
    with open('fst.bin', 'rb') as f:
        original = f.read()  # 86 bytes
    
    # Calculate padding needed for first part
    padding_length = BLOCK_SIZE - (len(original) % BLOCK_SIZE)  # = 10
    padding = bytes([padding_length] * padding_length)
    
    # Create first message part
    first_part = original[:BLOCK_SIZE]  # First block
    
    # Create the forgery
    forged_msg = bytearray()
    
    # First block remains unchanged
    forged_msg.extend(first_part)
    
    # Add second part that will help produce our target MAC
    # XOR first block with IV to cancel it out
    second_part = strxor(first_part, IV)
    # XOR with MAC to get our target
    second_part = strxor(second_part, mac_bytes)
    forged_msg.extend(second_part)
    
    # Add padding to complete the block
    forged_msg.extend(padding)
    
    print(f"Original length: {len(original)} bytes")
    print(f"Forged length: {len(forged_msg)} bytes")
    print("\nForged message blocks:")
    for i in range(0, len(forged_msg), BLOCK_SIZE):
        block = forged_msg[i:i+BLOCK_SIZE]
        print(f"Block {i//BLOCK_SIZE + 1}: {' '.join(f'{b:02x}' for b in block)}")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_msg)
    
    return MAC

def main():
    mac = create_forged_file()
    print(f"\nRun this command:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()