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
    
    # Create first block that's 15 bytes (to force specific padding)
    block_size = AES.block_size
    first_part = b"A" * (block_size - 1)  # 15 bytes
    
    # This will be padded with one 0x01 byte to complete the block
    padded_first = pad(first_part, block_size)
    
    # XOR operations
    xor_result = strxor(IV, padded_first)
    second_block = strxor(mac_bytes, xor_result)
    
    # Create forged message - using unpadded first part
    forged_input = first_part + second_block
    
    print("\nDetailed Analysis:")
    print("First part length:", len(first_part))
    print("Padded first part length:", len(padded_first))
    print("First part (hex):", first_part.hex())
    print("Padded first part (hex):", padded_first.hex())
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