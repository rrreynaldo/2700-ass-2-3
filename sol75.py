from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read files and setup
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()  # 86 bytes
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    IV = b'fedcba9876543210'
    block_size = AES.block_size
    
    # Get original blocks (should be 6 blocks after padding)
    padded_original = pad(original_msg, block_size)
    blocks = [padded_original[i:i+block_size] for i in range(0, len(padded_original), block_size)]
    
    # Following the example:
    # 1. Take first 5 blocks
    first_five = original_msg[:80]  # 5 blocks
    
    # 2. Calculate special block (xor of 1st block, IV and MAC)
    first_block = blocks[0]
    special_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # 3. Create forged message following the example structure:
    # - Original 5 blocks
    # - Special block (XOR result)
    # - Blocks 2-5 again
    forged_input = (
        first_five +              # First 5 blocks
        special_block +           # Special XOR block
        original_msg[16:80]       # Blocks 2-5 again
    )
    
    print("\nBlock Analysis:")
    print("Original blocks:")
    for i, block in enumerate(blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    print("\nForged Message Construction:")
    print(f"First five blocks: {first_five.hex()}")
    print(f"Special block: {special_block.hex()}")
    print(f"Repeated blocks 2-5: {original_msg[16:80].hex()}")
    
    print("\nFinal Message:")
    print(f"Length: {len(forged_input)}")
    print(f"Complete message: {forged_input.hex()}")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()