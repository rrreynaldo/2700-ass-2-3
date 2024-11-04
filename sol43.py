#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
import binascii

def create_forged_file():
    BLOCK_SIZE = 16
    IV = b'fedcba9876543210'
    
    # Read original file and MAC
    with open('fst.bin', 'rb') as f:
        original = f.read()  # 86 bytes
        
    with open('mac1.txt', 'r') as f:
        known_mac = f.read().strip()
    mac_bytes = binascii.unhexlify(known_mac)
    
    # Calculate the original padding
    # Original is 86 bytes
    # 86 % 16 = 6 (so needs 10 bytes of padding with value 0x0A)
    original_padded = pad(original, BLOCK_SIZE)
    
    # Create new message
    forged_msg = bytearray()
    
    # Take first 48 bytes (3 blocks) from padded original
    forged_msg.extend(original_padded[:3*BLOCK_SIZE])
    
    # Calculate XOR block
    first_block = original_padded[:BLOCK_SIZE]
    xor_block = strxor(strxor(first_block, IV), mac_bytes)
    forged_msg.extend(xor_block)
    
    # Add blocks 2 and 3 again
    forged_msg.extend(original_padded[BLOCK_SIZE:3*BLOCK_SIZE])
    
    # The message must be properly padded as per PKCS#7
    final_padded = pad(forged_msg, BLOCK_SIZE)
    
    print(f"Original length: {len(original)} bytes")
    print(f"Original padded length: {len(original_padded)} bytes")
    print(f"Final forged length: {len(final_padded)} bytes")
    print("\nMessage blocks:")
    for i in range(0, len(final_padded), BLOCK_SIZE):
        print(f"Block {i//BLOCK_SIZE + 1}: {' '.join(f'{b:02x}' for b in final_padded[i:i+BLOCK_SIZE])}")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(final_padded)
    
    return known_mac

def main():
    mac = create_forged_file()
    print(f"\nRun this exact command:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()