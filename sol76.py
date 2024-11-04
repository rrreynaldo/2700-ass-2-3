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
    
    # Original padded message analysis (86 bytes + 10 bytes padding = 96 bytes = 6 blocks)
    padded_original = pad(original_msg, block_size)
    blocks = [padded_original[i:i+block_size] for i in range(0, len(padded_original), block_size)]
    
    # Create forged message following example structure:
    # 1. Take first 5 complete blocks (80 bytes)
    first_five = original_msg[:80]
    
    # 2. Add padding to block 5 (same as original padding)
    padding_bytes = b'\x0a' * 10
    
    # 3. Calculate special block (6th block)
    first_block = blocks[0]
    special_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # 4. Add blocks 2-5 again
    remaining_blocks = original_msg[16:80]
    
    # 5. Combine everything
    forged_input = (
        first_five +          # First 5 blocks (80 bytes)
        padding_bytes +       # Add padding (10 bytes)
        special_block +       # Special XOR block (16 bytes)
        remaining_blocks      # Blocks 2-5 again (64 bytes)
    )
    
    print("\nOriginal Message Structure:")
    for i, block in enumerate(blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    print("\nForged Message Construction:")
    print(f"First five blocks (80 bytes): {first_five.hex()}")
    print(f"Padding (10 bytes): {padding_bytes.hex()}")
    print(f"Special block (16 bytes): {special_block.hex()}")
    print(f"Remaining blocks (64 bytes): {remaining_blocks.hex()}")
    
    print("\nFinal Message Details:")
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