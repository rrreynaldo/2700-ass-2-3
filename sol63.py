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
    
    # Original message is 86 bytes, when padded becomes 96 bytes (6 blocks)
    # Each block is 16 bytes
    block_size = AES.block_size
    padded_msg = pad(original_msg, block_size)
    
    # Calculate number of blocks needed
    num_blocks = len(padded_msg) // block_size  # Should be 6
    
    # Get first block
    first_block = original_msg[:block_size]
    
    # Calculate special block (XOR of first block, IV, and MAC)
    special_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # Construct forged message:
    # Original message (86 bytes) + 
    # Special block (16 bytes) +
    # Blocks 2-6 of original message (remaining blocks)
    forged_input = (
        original_msg +  # Original 86 bytes
        special_block +  # Special block for cycle
        original_msg[block_size:]  # Remaining blocks from original
    )
    
    print("\nDetailed Analysis:")
    print("Original message length:", len(original_msg))
    print("Padded message length:", len(padded_msg))
    print("Number of blocks in padded message:", num_blocks)
    print("First block (hex):", first_block.hex())
    print("IV (hex):", IV.hex())
    print("MAC from file (hex):", mac)
    print("Special block (hex):", special_block.hex())
    print("Forged input length:", len(forged_input))
    print("Forged input (hex):", forged_input.hex())
    
    # Debug - show each block
    for i in range(len(padded_msg) // block_size):
        start = i * block_size
        end = start + block_size
        print(f"Original Block {i+1}:", padded_msg[start:end].hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()