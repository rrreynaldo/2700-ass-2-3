from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Cipher.AES import block_size
import binascii

def debug_xor(a, b, label):
    result = strxor(a, b)
    print(f"\n{label}:")
    print(f"A: {a.hex()}")
    print(f"B: {b.hex()}")
    print(f"R: {result.hex()}")
    return result

def analyze_cbcmac():
    # Known values
    IV = b'fedcba9876543210'
    TARGET_MAC = "6983ed2550f04de595951aabed20d7b1"
    
    # Read original file
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    
    # Get padded version
    padded_msg = pad(original_msg, block_size)
    
    print("\nOriginal Message Analysis:")
    print(f"Original length: {len(original_msg)}")
    print(f"Padded length: {len(padded_msg)}")
    print(f"Number of blocks: {len(padded_msg) // block_size}")
    
    # Show all blocks
    blocks = [padded_msg[i:i+block_size] for i in range(0, len(padded_msg), block_size)]
    print("\nOriginal Message Blocks:")
    for i, block in enumerate(blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    # Let's try to understand CBC-MAC process
    # For first block: encrypt(x1 ⊕ IV)
    x1 = blocks[0]
    print("\nFirst Block Processing:")
    print(f"x1: {x1.hex()}")
    print(f"IV: {IV.hex()}")
    
    # Create forged message attempt 1:
    # Two blocks where second is calculated to force desired MAC
    first_block = x1
    desired_mac = binascii.unhexlify(TARGET_MAC)
    
    # Calculate what second block should be
    # We want: enc(b2 ⊕ enc(b1 ⊕ IV)) = target_mac
    xor_result = debug_xor(first_block, IV, "Step 1: first_block ⊕ IV")
    second_block = debug_xor(xor_result, desired_mac, "Step 2: result ⊕ target_mac")
    
    # Create and save forged message
    forged_msg = first_block + second_block
    
    print("\nForged Message:")
    print("First block:", first_block.hex())
    print("Second block:", second_block.hex())
    print("Complete:", forged_msg.hex())
    
    # Show padding that will be applied
    padded_forged = pad(forged_msg, block_size)
    print("\nPadding Analysis:")
    print("Before padding:", len(forged_msg))
    print("After padding:", len(padded_forged))
    print("Padded message:", padded_forged.hex())
    
    with open('snd.bin', 'wb') as f:
        f.write(forged_msg)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print('python3 cbcmac.py "1234567890123456" snd.bin')

if __name__ == "__main__":
    analyze_cbcmac()