from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original message and MAC
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
    
    # Extract blocks
    blocks = []
    for i in range(len(padded_original) // block_size):
        start = i * block_size
        end = start + block_size
        blocks.append(padded_original[start:end])
    
    # Calculate XOR for special block (block 6)
    # Following example: XOR of 1st block, IV and MAC
    first_block = blocks[0]
    special_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # Construct forged message following example structure:
    # Original 5 blocks (80 bytes) + 
    # Special block (XOR result) +
    # Repeat blocks 2,3,4,5 + 
    # Add padding in last block
    forged_input = (
        original_msg[:80] +      # First 5 blocks
        special_block +          # Special XOR block
        padded_original[16:80]   # Blocks 2-5
    )
    
    print("\nBlock Analysis:")
    print("Original msg length:", len(original_msg))
    print("Number of blocks after padding:", len(blocks))
    for i, block in enumerate(blocks):
        print(f"Block {i+1}:", block.hex())
    
    print("\nForged Message Details:")
    print("First block:", first_block.hex())
    print("IV:", IV.hex())
    print("MAC:", mac)
    print("Special block:", special_block.hex())
    print("Forged input length:", len(forged_input))
    print("Forged input hex:", forged_input.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()