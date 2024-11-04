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
    
    # Take exactly one block (16 bytes)
    x = original_msg[:block_size]
    
    # Important: Account for the fact that even perfect blocks get padded
    padded_x = pad(x, block_size)  # This adds a full block of padding
    
    # Calculate XORs considering padding
    xor1 = strxor(padded_x[:block_size], mac_bytes)  # Use first block of padded x
    second_block = strxor(xor1, IV)
    
    # Create forged message
    forged_input = x + second_block
    
    print("\nDetailed Analysis:")
    print("Original x block (hex):", x.hex())
    print("Padded x (hex):", padded_x.hex())
    print("Target MAC (hex):", mac)
    print("IV (hex):", IV.hex())
    
    print("\nXOR Operations:")
    print("1. padded_x first block ⊕ MAC:", xor1.hex())
    print("2. Result ⊕ IV (second block):", second_block.hex())
    
    print("\nForged Message:")
    print("Length:", len(forged_input))
    print("Message (hex):", forged_input.hex())
    
    # Analyze how it will be padded
    final_padded = pad(forged_input, block_size)
    print("\nPadding Analysis:")
    print("Before padding:", len(forged_input))
    print("After padding:", len(final_padded))
    print("Final padded form (hex):", final_padded.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()