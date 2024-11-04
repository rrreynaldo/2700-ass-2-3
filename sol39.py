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
    TARGET_BLOCKS = 10
    
    # Read original file
    with open('fst.bin', 'rb') as f:
        original = f.read()  # 86 bytes
    
    # Known MAC value
    MAC = "400b3f71959baf64ccfdb8f45d9246f3"
    mac_bytes = binascii.unhexlify(MAC)
    
    # Calculate proper PKCS#7 padding
    padding_length = BLOCK_SIZE - (len(original) % BLOCK_SIZE)  # = 10
    padding_value = padding_length  # = 0x0A
    padding = bytes([padding_value] * padding_length)
    
    # Create padded original (86 bytes + 10 bytes of 0x0A)
    padded_original = original + padding
    
    # Create forged message (exactly 10 blocks = 160 bytes)
    forged_msg = bytearray()
    
    # 1. First 5 blocks from original
    forged_msg.extend(padded_original[:5*BLOCK_SIZE])
    
    # 2. Block 6: padding block
    forged_msg.extend(padded_original[5*BLOCK_SIZE:6*BLOCK_SIZE])
    
    # 3. Block 7: XOR block
    first_block = original[:BLOCK_SIZE]
    xor_result = strxor(first_block, IV)
    xor_block = strxor(xor_result, mac_bytes)
    forged_msg.extend(xor_block)
    
    # 4. Blocks 8-10: Duplicate blocks 2-4
    forged_msg.extend(padded_original[BLOCK_SIZE:4*BLOCK_SIZE])
    
    # Verify length
    if len(forged_msg) != TARGET_BLOCKS * BLOCK_SIZE:
        print(f"Warning: Message length {len(forged_msg)} != expected {TARGET_BLOCKS * BLOCK_SIZE}")
    
    print("\nMessage structure:")
    print_hex_blocks(forged_msg)
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_msg)
    
    return MAC

def main():
    mac = create_forged_file()
    print(f"\nRun this exact command:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()