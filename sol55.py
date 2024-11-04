from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original message
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    
    # Read MAC from file
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Fixed IV from implementation
    IV = b'fedcba9876543210'
    
    # Pad the original message to block size
    block_size = AES.block_size
    padded_msg = pad(original_msg, block_size)
    
    # Take just the first block of padded message
    first_block = padded_msg[:block_size]
    
    # Calculate y ⊕ IV ⊕ x
    iv_xor_input = strxor(IV, first_block)  # First XOR: IV ⊕ x
    second_block = strxor(mac_bytes, iv_xor_input)  # Second XOR: y ⊕ (IV ⊕ x)
    
    # Create forged input: x || (y ⊕ IV ⊕ x)
    forged_input = first_block + second_block
    
    # Debug prints
    print("Original message length:", len(original_msg))
    print("Padded message length:", len(padded_msg))
    print("First block (hex):", first_block.hex())
    print("IV (hex):", IV.hex())
    print("MAC (hex):", mac)
    print("IV XOR first_block (hex):", iv_xor_input.hex())
    print("Second block (hex):", second_block.hex())
    print("Forged input length:", len(forged_input))
    print("Forged input (hex):", forged_input.hex())
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Use this command to verify:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()