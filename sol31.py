#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def create_forged_file():
    # Create a one-block message that will result in predictable padding
    # AES block size is 16 bytes
    block_size = AES.block_size
    
    # Create first message that's exactly one block minus one byte (15 bytes)
    # This will result in one byte of padding (0x01)
    msg1 = b'A' * (block_size - 1)
    
    # Create snd.bin with this content
    with open('snd.bin', 'wb') as f:
        f.write(msg1)
    
    # The MAC should be set to all zeros except the last byte
    # This exploits the fact that CBC-MAC uses the last block as the MAC
    # We choose a MAC that when XORed with our padding will give us a desired value
    forged_mac = '00' * 15 + '01'  # 16 bytes of all zeros except last byte
    
    return forged_mac

def main():
    mac = create_forged_file()
    print(f"Created snd.bin and generated MAC: {mac}")
    print("\nRun this command to verify:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    main()