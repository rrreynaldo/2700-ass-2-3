from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

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
    padded_original = pad(original_msg, block_size)
    blocks = [padded_original[i:i+block_size] for i in range(0, len(padded_original), block_size)]
    
    # Instead of using the first block, let's use block with padding
    x = padded_original[-block_size:]  # Last block (with 0x0a padding)
    
    # Create special second block
    # XOR with the MAC first, then with IV
    xor1 = strxor(x, mac_bytes)
    second_block = strxor(xor1, IV)
    
    # Create forged message
    # Use a block that includes correct padding
    first_block = original_msg[-block_size-1:-1] + bytes([0x0a])  # Create block with 0x0a padding
    forged_input = first_block + second_block
    
    print("\nDetailed Block Analysis:")
    print("Original message blocks:")
    for i, block in enumerate(blocks):
        print(f"Block {i+1}: {block.hex()}")
    
    print("\nForged Message Construction:")
    print("Using last padded block:", x.hex())
    print("Target MAC:", mac)
    print("IV:", IV.hex())
    print("XOR Steps:")
    print("1. x ⊕ MAC:", xor1.hex())
    print("2. (x ⊕ MAC) ⊕ IV:", second_block.hex())
    
    print("\nForged Message:")
    print("First block:", first_block.hex())
    print("Second block:", second_block.hex())
    print("Complete message:", forged_input.hex())
    
    # Test padding
    final_padded = pad(forged_input, block_size)
    print("\nPadding Test:")
    print("Original length:", len(forged_input))
    print("Padded length:", len(final_padded))
    print("Padded message:", final_padded.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()