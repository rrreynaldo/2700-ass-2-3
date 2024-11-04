from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original file and MAC
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()  # 86 bytes
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Fixed IV
    IV = b'fedcba9876543210'
    block_size = AES.block_size
    
    # Original message padded blocks analysis
    padded_original = pad(original_msg, block_size)  # 96 bytes (6 blocks)
    
    # Extract each block from padded original
    blocks = []
    for i in range(len(padded_original) // block_size):
        start = i * block_size
        end = start + block_size
        blocks.append(padded_original[start:end])
    
    # Construct the forgery:
    # 1. Take original message with padding removed from last block
    # 2. Add special XOR block after the 5th block
    # 3. Add padding block
    
    # Remove padding from original message
    unpadded_msg = original_msg  # Original 86 bytes
    
    # Calculate special block that creates the cycle
    first_block = blocks[0]  # First 16 bytes
    special_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # Construct forged message with specific structure:
    # Original 5 blocks + special block + original blocks + padding
    forged_input = (
        unpadded_msg +           # Original 86 bytes
        special_block +          # Our special XOR block
        blocks[1] + blocks[2] + blocks[3] + blocks[4]  # Original blocks 2-5
    )
    
    print("\nDetailed Block Analysis:")
    print("Original message length:", len(original_msg))
    print("Block size:", block_size)
    print("Number of original blocks:", len(blocks))
    for i, block in enumerate(blocks):
        print(f"Original Block {i+1}:", block.hex())
    
    print("\nForged Message Components:")
    print("First block (hex):", first_block.hex())
    print("IV (hex):", IV.hex())
    print("MAC from file (hex):", mac)
    print("Special block (hex):", special_block.hex())
    print("Forged input length:", len(forged_input))
    print("Forged input (hex):", forged_input.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()