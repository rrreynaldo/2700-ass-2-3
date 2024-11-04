from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def analyze_block_structure(data, block_size):
    """Analyze the block structure of data"""
    blocks = []
    padded = pad(data, block_size)
    for i in range(0, len(padded), block_size):
        blocks.append(padded[i:i+block_size])
    return blocks, padded

def create_forged_file():
    # Fixed IV
    IV = b'fedcba9876543210'
    block_size = AES.block_size
    
    # Read original message and MAC
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Analyze original message structure
    orig_blocks, padded_orig = analyze_block_structure(original_msg, block_size)
    
    print("\nOriginal Message Analysis:")
    print(f"Length: {len(original_msg)} bytes")
    print(f"Padded length: {len(padded_orig)} bytes")
    print(f"Number of blocks: {len(orig_blocks)}")
    print("Original blocks:")
    for i, block in enumerate(orig_blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    # Take first block as our x
    x = original_msg[:block_size]
    
    # Calculate each step of x' = x || (x ⊕ m ⊕ IV)
    print("\nAttack Construction:")
    print("1. First block x (hex):", x.hex())
    print("2. MAC m (hex):", mac)
    print("3. IV (hex):", IV.hex())
    
    # Calculate XOR chain
    xor_x_m = strxor(x, mac_bytes)
    xor_final = strxor(xor_x_m, IV)
    
    print("\nXOR Chain:")
    print("1. x ⊕ m:", xor_x_m.hex())
    print("2. (x ⊕ m) ⊕ IV:", xor_final.hex())
    
    # Create forged message
    forged_input = x + xor_final
    
    # Analyze forged message structure
    forged_blocks, padded_forged = analyze_block_structure(forged_input, block_size)
    
    print("\nForged Message Analysis:")
    print(f"Length: {len(forged_input)} bytes")
    print(f"Padded length: {len(padded_forged)} bytes")
    print(f"Number of blocks: {len(forged_blocks)}")
    print("Forged blocks:")
    for i, block in enumerate(forged_blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()