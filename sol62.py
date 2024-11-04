from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original file and MAC
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Fixed IV
    IV = b'fedcba9876543210'
    
    # Get the first block (16 bytes)
    first_block = original_msg[:16]
    
    # Calculate XOR of first block, IV and MAC for 6th block
    sixth_block = strxor(strxor(first_block, IV), mac_bytes)
    
    # Create the forged message:
    # Original message + sixth block + remaining blocks
    forged_input = (
        original_msg +  # Original 5 blocks
        sixth_block +   # Modified 6th block (XOR of 1st, IV, MAC)
        original_msg[16:] +  # Add blocks 2-5 again
        b'\x0b' * 11    # Add padding to match original
    )
    
    print("\nDetailed Analysis:")
    print("Original message length:", len(original_msg))
    print("First block (hex):", first_block.hex())
    print("IV (hex):", IV.hex())
    print("MAC from file (hex):", mac)
    print("Sixth block (hex):", sixth_block.hex())
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