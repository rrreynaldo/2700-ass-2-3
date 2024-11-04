from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Fixed IV from implementation
    IV = b'fedcba9876543210'
    
    # Read MAC from file
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Create a message that's one block
    block_size = AES.block_size
    first_block = b"A" * block_size
    
    # Generate the padding for verification
    padded_block = pad(first_block, block_size)
    
    # XOR operations
    xor_result = strxor(IV, first_block)  # Both are 16 bytes
    second_block = strxor(mac_bytes, xor_result)  # Both are 16 bytes
    
    # Create forged message
    forged_input = first_block + second_block
    
    print("\nDetailed Analysis:")
    print("Block size:", block_size)
    print("First block length:", len(first_block))
    print("First block (hex):", first_block.hex())
    print("IV (hex):", IV.hex())
    print("MAC from file (hex):", mac)
    print("XOR result (hex):", xor_result.hex())
    print("Second block (hex):", second_block.hex())
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